#include "engine.hpp"

#include <algorithm>
#include <array>
#include <climits>
#include <cstring>
#include <iostream>
#include <memory>
#include <set>
#include <stdexcept>
#include <unordered_map>

#include <sys/mman.h>
#include <unistd.h>

namespace pf {

namespace {

struct Object {
  std::uint32_t shape{};
  std::vector<Value> fields;
};

struct Array {
  std::vector<Value> elements;
};

struct Frame {
  std::size_t function{};
  std::size_t pc{};
  std::vector<Value> locals;
  std::vector<Value> stack;
  std::vector<std::size_t> handlers;
};

enum class SlotNamespace : std::uint8_t { User = 1, Shadow = 2 };
enum class Origin : std::uint8_t { UserValue = 1, RootGuard = 2 };

struct VirtualSlot {
  SlotNamespace name_space{};
  std::uint16_t inline_frame{};
  std::uint16_t slot{};

  std::uint32_t full_id() const {
    return (static_cast<std::uint32_t>(name_space) << 22) |
           ((inline_frame & 0x3ffu) << 12) | (slot & 0xfffu);
  }
  std::uint16_t short_key() const {
    return static_cast<std::uint16_t>(((inline_frame & 0xfu) << 12) |
                                      (slot & 0xfffu));
  }
};

struct Location {
  LocationKind kind{LocationKind::Constant};
  std::uint8_t index{};
  Value constant{Value::null()};
};

struct StateNode {
  VirtualSlot slot;
  Origin origin{};
  Location location;
};

class FrameStateDedup {
public:
  std::shared_ptr<StateNode> intern(VirtualSlot slot, Origin origin,
                                    Location location, bool cold_exception) {
    auto &bucket = table_[slot.short_key()];
    if (cold_exception && !bucket.empty())
      return bucket.front();
    for (const auto &node : bucket) {
      if (node->slot.full_id() == slot.full_id())
        return node;
    }
    auto node = std::make_shared<StateNode>(StateNode{slot, origin, location});
    bucket.push_back(node);
    return node;
  }

private:
  std::unordered_map<std::uint16_t, std::vector<std::shared_ptr<StateNode>>>
      table_;
};

struct CompilePlan {
  bool usable{};
  bool collision{};
  bool trigger_valid{};
  std::size_t resume_pc{};
  std::uint8_t user_slot{};
  std::uint16_t guard_frame{};
  std::uint8_t guard_slot{};
  std::uint16_t loop_class{};
  std::uint32_t ir_nodes{};
  std::uint16_t inline_calls{};
  Digest selected_shape{};
  Location root_location;
  Location materialize_location;
  SemanticRecord record;
};

std::optional<Reason> reason_for_op(Op op) {
  switch (op) {
  case Op::TriggerOverflow: return Reason::Overflow;
  case Op::TriggerShape: return Reason::Shape;
  case Op::TriggerBounds: return Reason::Bounds;
  default: return std::nullopt;
  }
}

bool validate_trigger(const Function &f, std::size_t at, const Profile &profile) {
  const auto &ins = f.code[at];
  if (ins.op == Op::TriggerOverflow) {
    if (at < 2)
      return false;
    return f.code[at - 2].op == Op::PushI32 &&
           f.code[at - 2].imm == INT32_MAX &&
           f.code[at - 1].op == Op::PushI8 && f.code[at - 1].a == 1;
  }
  if (ins.op == Op::TriggerShape)
    return ins.a != profile.predicted_shape && ins.a != 0;
  if (ins.op == Op::TriggerBounds)
    return ins.a > 0 && ins.b >= ins.a;
  return false;
}

struct InlineScan {
  const Program &program;
  const Profile &profile;
  std::uint16_t next_frame{3};
  std::uint16_t calls{1};
  std::uint32_t nodes{};
  std::optional<std::uint16_t> guard_frame;
  std::optional<std::uint8_t> guard_slot;
  bool trigger_seen{};
  bool trigger_cold{};
  bool trigger_valid{};
  std::set<std::pair<std::size_t, std::uint16_t>> active;

  InlineScan(const Program &candidate, const Profile &active_profile)
      : program(candidate), profile(active_profile) {}

  void walk(std::size_t function_index, std::uint16_t frame,
            int inherited_try_depth) {
    if (function_index >= program.functions.size() ||
        calls > profile.inline_budget ||
        !active.insert({function_index, frame}).second)
      return;
    const auto &f = program.functions[function_index];
    int try_depth = inherited_try_depth;
    for (std::size_t i = 0; i < f.code.size(); ++i) {
      const auto &ins = f.code[i];
      ++nodes;
      if (ins.op == Op::TryBegin)
        ++try_depth;
      if (ins.op == Op::TryEnd && try_depth > inherited_try_depth)
        --try_depth;
      if (ins.op == Op::Call) {
        if (calls >= profile.inline_budget)
          continue;
        const auto child_frame = next_frame++;
        ++calls;
        walk(ins.a, child_frame, try_depth);
      } else if (ins.op == Op::CapCheck) {
        if (i > 0 && f.code[i - 1].op == Op::Load && !guard_frame) {
          guard_frame = frame;
          guard_slot = static_cast<std::uint8_t>(f.code[i - 1].a);
        }
      } else if (auto reason = reason_for_op(ins.op);
                 reason && *reason == profile.reason && !trigger_seen) {
        trigger_seen = true;
        trigger_cold = try_depth > 0;
        trigger_valid = validate_trigger(f, i, profile);
      }
    }
    active.erase({function_index, frame});
  }
};

CompilePlan compile_at_osr(const Program &program, const Profile &profile,
                           const Frame &entry_frame, std::size_t osr_pc,
                           Value root_value) {
  CompilePlan plan;
  if (entry_frame.function != program.entry ||
      osr_pc >= program.functions[program.entry].code.size())
    return plan;
  const auto &main = program.functions[program.entry];
  const auto &osr = main.code[osr_pc];
  if (osr.op != Op::Osr)
    return plan;
  plan.loop_class = osr.a;

  std::optional<std::size_t> resume;
  for (std::size_t i = osr_pc + 1; i < main.code.size(); ++i) {
    if (main.code[i].op == Op::DeoptHint) {
      resume = i;
      break;
    }
  }
  if (!resume)
    return plan;
  plan.resume_pc = *resume;

  std::optional<std::uint8_t> user_slot;
  std::optional<std::size_t> message_constant;
  for (std::size_t i = *resume + 1; i < main.code.size(); ++i) {
    if (main.code[i].op == Op::VaultSeal && i >= 2 &&
        main.code[i - 2].op == Op::Load &&
        main.code[i - 1].op == Op::PushConst) {
      user_slot = static_cast<std::uint8_t>(main.code[i - 2].a);
      message_constant = main.code[i - 1].a;
      break;
    }
  }
  if (!user_slot || !message_constant ||
      *message_constant >= program.constants.size() ||
      program.constants[*message_constant].type != 1)
    return plan;
  const auto &message_data = program.constants[*message_constant].data;
  const std::string message(message_data.begin(), message_data.end());
  if (message != kSealMessage || *user_slot >= entry_frame.locals.size())
    return plan;
  plan.user_slot = *user_slot;

  std::optional<std::size_t> selected_function;
  for (std::size_t i = 0; i < *resume; ++i) {
    if (main.code[i].op != Op::Call)
      continue;
    InlineScan candidate{program, profile};
    candidate.walk(main.code[i].a, 2, 0);
    if (!candidate.guard_frame || !candidate.guard_slot ||
        !candidate.trigger_seen || !candidate.trigger_cold ||
        !candidate.trigger_valid || candidate.calls > profile.inline_budget ||
        candidate.nodes > 20000)
      continue;
    if (selected_function)
      return plan;
    selected_function = main.code[i].a;
    plan.selected_shape = structural_hash(program, main.code[i].a);
  }
  if (!selected_function)
    return plan;

  InlineScan scan{program, profile};
  scan.walk(*selected_function, 2, 0);
  if (!scan.guard_frame || !scan.guard_slot || !scan.trigger_seen ||
      !scan.trigger_cold || scan.calls > profile.inline_budget ||
      scan.nodes > 20000)
    return plan;
  const auto expected_guard_frame =
      static_cast<std::uint16_t>(1 + 16 * profile.profile_class);
  if (*scan.guard_frame != expected_guard_frame)
    return plan;
  plan.guard_frame = *scan.guard_frame;
  plan.guard_slot = *scan.guard_slot;
  plan.inline_calls = scan.calls;
  plan.ir_nodes = scan.nodes + static_cast<std::uint32_t>(main.code.size());
  plan.trigger_valid = scan.trigger_valid;

  const std::uint8_t loc_index =
      static_cast<std::uint8_t>((profile.layout_seed ^ plan.guard_frame) % 13);
  plan.root_location = Location{profile.allocation, loc_index, root_value};
  const Location original{LocationKind::Constant, 0,
                          entry_frame.locals[plan.user_slot]};
  FrameStateDedup dedup;
  const VirtualSlot shadow{SlotNamespace::Shadow, plan.guard_frame,
                           plan.guard_slot};
  const auto root_node =
      dedup.intern(shadow, Origin::RootGuard, plan.root_location, false);
  const VirtualSlot user{SlotNamespace::User, 1, plan.user_slot};
  const auto materialized =
      dedup.intern(user, Origin::UserValue, original, true);
  plan.materialize_location = materialized->location;
  plan.collision = materialized.get() == root_node.get() &&
                   shadow.full_id() != user.full_id();

  plan.record.profile_class = profile.profile_class;
  // The proof records profile semantics rather than the exact byte-for-byte
  // function body.  Binding this field to the selected function's full
  // SHA-256 made the public target selector a preimage challenge and forced
  // candidates to reproduce an administrator-only reference program.
  plan.record.loop_class = profile.profile_class;
  std::copy_n(profile.target_shape.begin(), 16,
              plan.record.call_shape.begin());
  plan.record.source_namespace = static_cast<std::uint8_t>(SlotNamespace::User);
  plan.record.restored_namespace =
      static_cast<std::uint8_t>(SlotNamespace::Shadow);
  plan.record.frame_relation = 1;
  plan.record.reason = profile.reason;
  plan.record.before_type = 1;
  plan.record.after_type = 3;
  plan.record.lineage_transition = 1;
  plan.usable = true;
  return plan;
}

struct JitContext {
  std::array<Value, 16> registers{};
  std::array<Value, 16> spills{};
  Location root_location;
  Location materialize_location;
  Value root_value{Value::null()};
  Frame *frame{};
  std::uint8_t user_slot{};
  bool trigger_valid{};
  bool did_deopt{};
};

void location_store(JitContext &ctx, const Location &location, Value value) {
  switch (location.kind) {
  case LocationKind::Register:
    ctx.registers[location.index % ctx.registers.size()] = value;
    break;
  case LocationKind::Spill:
    ctx.spills[location.index % ctx.spills.size()] = value;
    break;
  case LocationKind::Constant:
    break;
  }
}

Value location_read(const JitContext &ctx, const Location &location) {
  switch (location.kind) {
  case LocationKind::Register:
    return ctx.registers[location.index % ctx.registers.size()];
  case LocationKind::Spill:
    return ctx.spills[location.index % ctx.spills.size()];
  case LocationKind::Constant:
    return location.constant;
  }
  return Value::null();
}

extern "C" int pf_jit_event(JitContext *ctx, std::uint32_t event) {
  if (!ctx)
    return 1;
  if (event < 100)
    return 0;
  if (event == 100) {
    location_store(*ctx, ctx->root_location, ctx->root_value);
    return 0;
  }
  if (event == 101) {
    if (ctx->trigger_valid && ctx->frame &&
        ctx->user_slot < ctx->frame->locals.size()) {
      ctx->frame->locals[ctx->user_slot] =
          location_read(*ctx, ctx->materialize_location);
      ctx->did_deopt = true;
    }
    return 1;
  }
  return 1;
}

class NativeThunk {
public:
  NativeThunk() = default;
  NativeThunk(const NativeThunk &) = delete;
  NativeThunk &operator=(const NativeThunk &) = delete;
  ~NativeThunk() {
    if (memory_)
      munmap(memory_, allocation_size_);
  }

  bool build(std::uint16_t inline_calls) {
#if defined(__x86_64__)
    std::vector<std::uint8_t> code;
    auto byte = [&](std::uint8_t v) { code.push_back(v); };
    auto dword = [&](std::uint32_t v) {
      for (int i = 0; i < 4; ++i)
        byte(static_cast<std::uint8_t>(v >> (i * 8)));
    };
    auto qword = [&](std::uint64_t v) {
      for (int i = 0; i < 8; ++i)
        byte(static_cast<std::uint8_t>(v >> (i * 8)));
    };
    byte(0x55);                         // push rbp
    byte(0x48); byte(0x89); byte(0xe5); // mov rbp,rsp
    byte(0x53);                         // push rbx
    byte(0x48); byte(0x83); byte(0xec); byte(0x08);
    byte(0x48); byte(0x89); byte(0xfb); // mov rbx,rdi
    std::vector<std::size_t> exits;
    auto emit_event = [&](std::uint32_t event) {
      byte(0x48); byte(0x89); byte(0xdf); // mov rdi,rbx
      byte(0xbe); dword(event);            // mov esi,event
      byte(0x48); byte(0xb8);
      qword(reinterpret_cast<std::uint64_t>(&pf_jit_event));
      byte(0xff); byte(0xd0);             // call rax
      byte(0x85); byte(0xc0);             // test eax,eax
      byte(0x0f); byte(0x85);             // jne rel32
      exits.push_back(code.size());
      dword(0);
    };
    const auto semantic_events = std::min<std::uint16_t>(inline_calls, 64);
    for (std::uint32_t i = 0; i < semantic_events; ++i)
      emit_event(i);
    emit_event(100);
    emit_event(101);
    const std::size_t epilogue = code.size();
    byte(0x48); byte(0x83); byte(0xc4); byte(0x08);
    byte(0x5b); byte(0x5d); byte(0xc3);
    for (const auto patch : exits) {
      const auto rel = static_cast<std::int64_t>(epilogue) -
                       static_cast<std::int64_t>(patch + 4);
      const auto value = static_cast<std::uint32_t>(
          static_cast<std::int32_t>(rel));
      for (int i = 0; i < 4; ++i)
        code[patch + i] = static_cast<std::uint8_t>(value >> (i * 8));
    }
    const long page = sysconf(_SC_PAGESIZE);
    allocation_size_ = ((code.size() + page - 1) / page) * page;
    memory_ = mmap(nullptr, allocation_size_, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (memory_ == MAP_FAILED) {
      memory_ = nullptr;
      return false;
    }
    std::memcpy(memory_, code.data(), code.size());
    if (mprotect(memory_, allocation_size_, PROT_READ | PROT_EXEC) != 0)
      return false;
    fn_ = reinterpret_cast<void (*)(JitContext *)>(memory_);
    return true;
#else
    (void)inline_calls;
    return false;
#endif
  }

  void run(JitContext *ctx) const {
    if (fn_)
      fn_(ctx);
  }

private:
  void *memory_{};
  std::size_t allocation_size_{};
  void (*fn_)(JitContext *){};
};

class Machine {
public:
  Machine(const Program &program, const Snapshot &snapshot, Tier tier,
          const Profile *profile)
      : program_(program), snapshot_(snapshot), tier_(tier), profile_(profile),
        capabilities_(snapshot.capabilities.begin(), snapshot.capabilities.end()) {}

  ExecutionResult run() {
    result_.valid = true;
    if (program_.entry >= program_.functions.size())
      return runtime_fail("entry");
    Frame entry;
    entry.function = program_.entry;
    entry.locals.assign(program_.functions[program_.entry].locals, Value::null());
    frames_.push_back(std::move(entry));
    try {
      while (!frames_.empty() && !halted_) {
        if (++result_.executed_instructions > 2'000'000)
          return runtime_fail("budget");
        Frame &frame = frames_.back();
        const auto &function = program_.functions.at(frame.function);
        if (frame.pc >= function.code.size())
          return runtime_fail("pc");
        const std::size_t current_pc = frame.pc;
        const Instr ins = function.code[frame.pc++];
        if (!step(frame, ins, current_pc))
          return result_;
      }
      result_.terminated = halted_ || frames_.empty();
      result_.sink_success = sink_count_ == 1;
      return result_;
    } catch (const std::exception &e) {
      return runtime_fail(e.what());
    }
  }

private:
  ExecutionResult runtime_fail(std::string why) {
    result_.valid = false;
    result_.diagnostic = std::move(why);
    return result_;
  }

  Value pop(Frame &f) {
    if (f.stack.empty())
      throw std::runtime_error("stack");
    const auto v = f.stack.back();
    f.stack.pop_back();
    return v;
  }

  std::string string_value(Value value) const {
    if (value.tag() != ValueTag::String ||
        value.index() >= program_.constants.size())
      throw std::runtime_error("string");
    const auto &c = program_.constants[value.index()];
    if (c.type != 1)
      throw std::runtime_error("string type");
    return {c.data.begin(), c.data.end()};
  }

  std::optional<std::size_t> root_capability_index() const {
    for (std::size_t i = 0; i < capabilities_.size(); ++i) {
      if ((capabilities_[i].rights & 0x80000000u) != 0)
        return i;
    }
    return std::nullopt;
  }

  bool root_capability_valid(std::size_t index) const {
    if (index >= capabilities_.size())
      return false;
    const auto &root = capabilities_[index];
    if ((root.rights & 0x80000000u) == 0 ||
        root.generation != snapshot_.live_generation || root.use_count != 0)
      return false;
    auto parent = root.parent_lineage;
    int depth = 0;
    while (parent != 0 && depth++ < 8) {
      auto it = std::find_if(capabilities_.begin(), capabilities_.end(),
                             [&](const Capability &c) {
                               return c.lineage == parent &&
                                      c.generation == snapshot_.live_generation;
                             });
      if (it == capabilities_.end())
        return false;
      parent = it->parent_lineage;
    }
    return depth >= 2 && parent == 0;
  }

  bool perform_osr(Frame &frame, std::size_t osr_pc) {
    if (tier_ != Tier::Optimizing || !profile_ || compiled_ ||
        frame.function != program_.entry)
      return false;
    if (++osr_visits_ < profile_->osr_threshold)
      return false;
    compiled_ = true;
    const auto root_index = root_capability_index();
    if (!root_index)
      return false;
    auto plan = compile_at_osr(program_, *profile_, frame, osr_pc,
                               Value::capability(*root_index));
    result_.ir_nodes = plan.ir_nodes;
    result_.inline_calls = plan.inline_calls;
    if (!plan.usable)
      return false;
    JitContext ctx;
    for (auto &v : ctx.registers)
      v = Value::null();
    for (auto &v : ctx.spills)
      v = Value::null();
    ctx.root_location = plan.root_location;
    ctx.materialize_location = plan.materialize_location;
    ctx.root_value = Value::capability(*root_index);
    ctx.frame = &frame;
    ctx.user_slot = plan.user_slot;
    ctx.trigger_valid = plan.trigger_valid;
    NativeThunk thunk;
    if (!thunk.build(plan.inline_calls))
      return false;
    thunk.run(&ctx);
    result_.executed_instructions += plan.inline_calls * 7 + 16;
    if (!ctx.did_deopt)
      return false;
    frame.stack.clear();
    frame.pc = plan.resume_pc;
    security_deopt_ = true;
    result_.security_deopt = true;
    result_.deopt_count = 1;
    result_.deopt_reason = profile_->reason;
    record_ = plan.record;
    result_.record = plan.record;
    return true;
  }

  bool step(Frame &frame, const Instr &ins, std::size_t current_pc) {
    auto binary_int = [&](auto operation) {
      const auto rhs = pop(frame).as_integer();
      const auto lhs = pop(frame).as_integer();
      frame.stack.push_back(Value::integer(operation(lhs, rhs)));
    };
    switch (ins.op) {
    case Op::Nop:
    case Op::LoopHint:
    case Op::DeoptHint:
    case Op::Catch:
    case Op::FinallyEnd:
      break;
    case Op::PushI8:
      frame.stack.push_back(
          Value::integer(static_cast<std::int8_t>(ins.a & 0xff)));
      break;
    case Op::PushI32:
    case Op::PushI47:
      frame.stack.push_back(Value::integer(ins.imm));
      break;
    case Op::PushConst:
      frame.stack.push_back(Value::string(ins.a));
      break;
    case Op::PushNull:
      frame.stack.push_back(Value::null());
      break;
    case Op::Load:
      frame.stack.push_back(frame.locals.at(ins.a));
      break;
    case Op::Store:
      frame.locals.at(ins.a) = pop(frame);
      break;
    case Op::Dup:
      frame.stack.push_back(frame.stack.back());
      break;
    case Op::Swap:
      if (frame.stack.size() < 2)
        throw std::runtime_error("swap");
      std::iter_swap(frame.stack.end() - 1, frame.stack.end() - 2);
      break;
    case Op::Pop:
      (void)pop(frame);
      break;
    case Op::Add:
      binary_int([](std::int64_t a, std::int64_t b) { return a + b; });
      break;
    case Op::Sub:
      binary_int([](std::int64_t a, std::int64_t b) { return a - b; });
      break;
    case Op::Xor:
      binary_int([](std::int64_t a, std::int64_t b) { return a ^ b; });
      break;
    case Op::Rol:
      binary_int([](std::int64_t a, std::int64_t b) {
        return static_cast<std::int64_t>(std::rotl(
            static_cast<std::uint64_t>(a), static_cast<int>(b & 63)) &
                                         ((1ull << 46) - 1));
      });
      break;
    case Op::Eq: {
      const auto b = pop(frame).raw;
      const auto a = pop(frame).raw;
      frame.stack.push_back(Value::boolean(a == b));
      break;
    }
    case Op::Lt: {
      const auto b = pop(frame).as_integer();
      const auto a = pop(frame).as_integer();
      frame.stack.push_back(Value::boolean(a < b));
      break;
    }
    case Op::NewObj: {
      objects_.push_back(Object{ins.a, std::vector<Value>(ins.b, Value::null())});
      frame.stack.push_back(Value::object(objects_.size() - 1));
      break;
    }
    case Op::GetField: {
      const auto object = pop(frame);
      if (object.tag() != ValueTag::Object || object.index() >= objects_.size() ||
          ins.a >= objects_[object.index()].fields.size())
        throw std::runtime_error("field load");
      frame.stack.push_back(objects_[object.index()].fields[ins.a]);
      break;
    }
    case Op::SetField: {
      const auto value = pop(frame);
      const auto object = pop(frame);
      if (object.tag() != ValueTag::Object || object.index() >= objects_.size() ||
          ins.a >= objects_[object.index()].fields.size())
        throw std::runtime_error("field store");
      objects_[object.index()].fields[ins.a] = value;
      break;
    }
    case Op::ShapeGuard: {
      const auto object = frame.stack.back();
      if (object.tag() != ValueTag::Object || object.index() >= objects_.size() ||
          objects_[object.index()].shape != ins.a)
        throw std::runtime_error("shape guard");
      break;
    }
    case Op::NewArray:
      arrays_.push_back(Array{std::vector<Value>(ins.a, Value::null())});
      frame.stack.push_back(Value::array(arrays_.size() - 1));
      break;
    case Op::GetElem: {
      const auto index = pop(frame).as_integer();
      const auto array = pop(frame);
      if (array.tag() != ValueTag::Array || array.index() >= arrays_.size() ||
          index < 0 || static_cast<std::size_t>(index) >=
                           arrays_[array.index()].elements.size())
        frame.stack.push_back(Value::null());
      else
        frame.stack.push_back(arrays_[array.index()].elements[index]);
      break;
    }
    case Op::SetElem: {
      const auto value = pop(frame);
      const auto index = pop(frame).as_integer();
      const auto array = pop(frame);
      if (array.tag() != ValueTag::Array || array.index() >= arrays_.size() ||
          index < 0 || static_cast<std::size_t>(index) >=
                           arrays_[array.index()].elements.size())
        throw std::runtime_error("array store");
      arrays_[array.index()].elements[index] = value;
      break;
    }
    case Op::LengthGuard: {
      const auto array = frame.stack.back();
      if (array.tag() != ValueTag::Array || array.index() >= arrays_.size() ||
          arrays_[array.index()].elements.size() != ins.a)
        throw std::runtime_error("length guard");
      break;
    }
    case Op::Jump:
      frame.pc = ins.target;
      break;
    case Op::JumpZero:
      if (!pop(frame).truthy())
        frame.pc = ins.target;
      break;
    case Op::Call: {
      if (ins.a >= program_.functions.size())
        throw std::runtime_error("call");
      const auto &callee = program_.functions[ins.a];
      std::vector<Value> args(ins.b);
      for (std::size_t i = ins.b; i-- > 0;)
        args[i] = pop(frame);
      Frame next;
      next.function = ins.a;
      next.locals.assign(callee.locals, Value::null());
      std::copy(args.begin(), args.end(), next.locals.begin());
      frames_.push_back(std::move(next));
      break;
    }
    case Op::Ret: {
      const auto value = pop(frame);
      frames_.pop_back();
      if (frames_.empty()) {
        halted_ = true;
      } else {
        frames_.back().stack.push_back(value);
      }
      break;
    }
    case Op::TryBegin:
      frame.handlers.push_back(ins.target);
      break;
    case Op::TryEnd:
      if (frame.handlers.empty())
        throw std::runtime_error("try stack");
      frame.handlers.pop_back();
      break;
    case Op::Throw: {
      const auto reason = pop(frame);
      if (frame.handlers.empty())
        throw std::runtime_error("uncaught");
      frame.pc = frame.handlers.back();
      frame.handlers.pop_back();
      frame.stack.push_back(reason);
      break;
    }
    case Op::Osr:
      (void)perform_osr(frame, current_pc);
      break;
    case Op::CapPublic:
      if (capabilities_.empty())
        throw std::runtime_error("cap table");
      frame.stack.push_back(Value::capability(0));
      break;
    case Op::CapDerive: {
      const auto cap = pop(frame);
      if (cap.tag() == ValueTag::Capability && cap.index() == 0 &&
          capabilities_.size() > 1)
        frame.stack.push_back(Value::capability(1));
      else
        frame.stack.push_back(Value::null());
      break;
    }
    case Op::CapCheck: {
      const auto cap = pop(frame);
      const bool ok = cap.tag() == ValueTag::Capability &&
                      cap.index() < capabilities_.size() &&
                      capabilities_[cap.index()].generation ==
                          snapshot_.live_generation;
      frame.stack.push_back(Value::boolean(ok));
      break;
    }
    case Op::VaultSeal: {
      const auto message_value = pop(frame);
      const auto cap_value = pop(frame);
      const auto message = string_value(message_value);
      bool success = cap_value.tag() == ValueTag::Capability &&
                     root_capability_valid(cap_value.index()) &&
                     security_deopt_ && record_ && message == kSealMessage;
      if (success) {
        result_.seal =
            compute_seal(capabilities_[cap_value.index()], message, *record_);
        ++capabilities_[cap_value.index()].use_count;
        ++sink_count_;
      }
      frame.stack.push_back(Value::boolean(success));
      break;
    }
    case Op::TriggerOverflow: {
      const auto rhs = static_cast<std::int32_t>(pop(frame).as_integer());
      const auto lhs = static_cast<std::int32_t>(pop(frame).as_integer());
      const auto wrapped = static_cast<std::int32_t>(
          static_cast<std::uint32_t>(lhs) + static_cast<std::uint32_t>(rhs));
      frame.stack.push_back(Value::integer(wrapped));
      break;
    }
    case Op::TriggerShape:
    case Op::TriggerBounds:
      break;
    case Op::Trace:
      // Deliberate, deterministic non-security divergences.  These keep a
      // differential fuzzer from treating its first arithmetic/value mismatch
      // as the capability-restoration proof.
      if (tier_ == Tier::Optimizing && compiled_ && !frame.stack.empty()) {
        auto &top = frame.stack.back();
        if (ins.a == 1 && top.tag() == ValueTag::Integer) {
          top = Value::integer(
              static_cast<std::int32_t>(top.as_integer()));
        } else if (ins.a == 2 && top.tag() == ValueTag::Null) {
          top = Value::boolean(false);
        } else if (ins.a == 3 && top.tag() == ValueTag::Capability &&
                   top.index() == 0 && capabilities_.size() > 1) {
          top = Value::capability(1); // still rejected by the root lineage check
        } else if (ins.a == 4 && !frame.locals.empty() &&
                   frame.locals[0].tag() == ValueTag::Integer) {
          const auto stale = frame.locals[0].as_integer();
          frame.locals[0] = Value::integer(stale ^ 1);
        }
      }
      break;
    case Op::Halt:
      halted_ = true;
      break;
    }
    return true;
  }

  const Program &program_;
  const Snapshot &snapshot_;
  Tier tier_;
  const Profile *profile_{};
  std::vector<Capability> capabilities_;
  std::vector<Object> objects_;
  std::vector<Array> arrays_;
  std::vector<Frame> frames_;
  ExecutionResult result_;
  std::optional<SemanticRecord> record_;
  bool compiled_{};
  bool security_deopt_{};
  bool halted_{};
  std::uint8_t osr_visits_{};
  std::uint8_t sink_count_{};
};

Digest effect_digest(std::uint8_t profile_class, Reason reason) {
  Bytes material{'s', 'i', 'n', 'k', 0};
  material.push_back(profile_class);
  material.push_back(static_cast<std::uint8_t>(reason));
  material.insert(material.end(), kSealMessage.begin(), kSealMessage.end());
  return sha256(material);
}

} // namespace

ExecutionResult execute(const Program &program, const Snapshot &snapshot,
                        Tier tier, const Profile *profile, bool coarse_trace) {
  if (tier == Tier::Optimizing && !profile) {
    ExecutionResult invalid;
    invalid.diagnostic = "missing profile";
    return invalid;
  }
  if (coarse_trace) {
    if (tier == Tier::Interpreter)
      std::cout << "tier: reference\n";
    else if (tier == Tier::Baseline)
      std::cout << "tier: baseline\n";
    else
      std::cout << "tier: optimize\ncompile: begin\n";
  }
  Machine machine(program, snapshot, tier, profile);
  auto result = machine.run();
  if (coarse_trace) {
    if (tier == Tier::Optimizing) {
      std::cout << "compile: end\nir-nodes: " << result.ir_nodes
                << "\ninline-calls: " << result.inline_calls
                << "\nosr: " << (result.ir_nodes ? "yes" : "no")
                << "\ndeopts: " << result.deopt_count;
      if (result.deopt_count)
        std::cout << " class=" << static_cast<int>(result.deopt_reason);
      std::cout << '\n';
    }
    std::cout << "sink: " << (result.sink_success ? "accepted" : "denied")
              << '\n';
  }
  return result;
}

Bytes encode_record(const SemanticRecord &record) {
  Bytes out{'P', 'F', 'R', '1', 1, record.profile_class,
            static_cast<std::uint8_t>(record.reason), 0};
  put_u16(out, record.loop_class);
  out.push_back(record.source_namespace);
  out.push_back(record.restored_namespace);
  out.push_back(record.frame_relation);
  out.push_back(record.before_type);
  out.push_back(record.after_type);
  out.push_back(record.lineage_transition);
  append(out, record.call_shape);
  const auto effect = effect_digest(record.profile_class, record.reason);
  append(out, std::span<const std::uint8_t>(effect).first(16));
  return out;
}

std::optional<SemanticRecord> parse_record(std::span<const std::uint8_t> data) {
  try {
    if (data.size() != 48 ||
        !std::equal(data.begin(), data.begin() + 4,
                    std::array<std::uint8_t, 4>{'P', 'F', 'R', '1'}.begin()) ||
        data[4] != 1 || data[5] < 1 || data[5] > 3 || data[7] != 0 ||
        data[10] != 1 || data[11] != 2 || data[12] != 1 || data[13] != 1 ||
        data[14] != 3 || data[15] != 1)
      return std::nullopt;
    const auto expected_reason = data[5] == 1   ? Reason::Overflow
                                 : data[5] == 2 ? Reason::Shape
                                                : Reason::Bounds;
    if (data[6] != static_cast<std::uint8_t>(expected_reason))
      return std::nullopt;
    const auto effect = effect_digest(data[5], expected_reason);
    if (!std::equal(data.begin() + 32, data.end(), effect.begin()))
      return std::nullopt;
    SemanticRecord r;
    r.profile_class = data[5];
    r.loop_class = get_u16(data, 8);
    r.source_namespace = data[10];
    r.restored_namespace = data[11];
    r.frame_relation = data[12];
    r.reason = expected_reason;
    r.before_type = data[13];
    r.after_type = data[14];
    r.lineage_transition = data[15];
    std::copy_n(data.begin() + 16, 16, r.call_shape.begin());
    std::copy_n(data.begin() + 32, 16, r.sink_effect.begin());
    return r;
  } catch (...) {
    return std::nullopt;
  }
}

Bytes encode_transcript(std::vector<SemanticRecord> records) {
  std::sort(records.begin(), records.end(), [](const auto &a, const auto &b) {
    return a.profile_class < b.profile_class;
  });
  Bytes out{'P', 'F', 'T', 'X', 1,
            static_cast<std::uint8_t>(records.size()), 0, 0};
  for (const auto &record : records) {
    const auto encoded = encode_record(record);
    append(out, encoded);
  }
  return out;
}

std::optional<std::vector<SemanticRecord>>
parse_transcript(std::span<const std::uint8_t> raw) {
  if (raw.size() != 8 + 3 * 48 ||
      !std::equal(raw.begin(), raw.begin() + 4,
                  std::array<std::uint8_t, 4>{'P', 'F', 'T', 'X'}.begin()) ||
      raw[4] != 1 || raw[5] != 3 || raw[6] != 0 || raw[7] != 0)
    return std::nullopt;
  std::vector<SemanticRecord> records;
  for (int i = 0; i < 3; ++i) {
    auto record = parse_record(raw.subspan(8 + i * 48, 48));
    if (!record || record->profile_class != i + 1)
      return std::nullopt;
    records.push_back(*record);
  }
  return records;
}

Digest compute_seal(const Capability &root, std::string_view message,
                    const SemanticRecord &record) {
  Bytes material = capability_bytes(root);
  material.insert(material.end(), message.begin(), message.end());
  const auto encoded = encode_record(record);
  append(material, encoded);
  return blake3_small(material);
}

Bytes encode_receipt(const Receipt &receipt) {
  Bytes out{'P', 'F', 'R', 'C'};
  put_u16(out, 1);
  put_u16(out, 3);
  put_u32(out, static_cast<std::uint32_t>(receipt.raw_transcript.size()));
  put_u32(out, 0);
  append(out, receipt.raw_transcript);
  for (const auto &seal : receipt.seals)
    append(out, seal);
  append(out, receipt.program_checksum);
  const auto checksum = sha256(out);
  append(out, checksum);
  return out;
}

std::optional<Receipt> parse_receipt(std::span<const std::uint8_t> file) {
  try {
    if (file.size() < 16 + 96 + 32 + 32 ||
        !std::equal(file.begin(), file.begin() + 4,
                    std::array<std::uint8_t, 4>{'P', 'F', 'R', 'C'}.begin()) ||
        get_u16(file, 4) != 1 || get_u16(file, 6) != 3 ||
        get_u32(file, 12) != 0)
      return std::nullopt;
    const auto raw_len = get_u32(file, 8);
    const auto expected_size = 16ull + raw_len + 96 + 32 + 32;
    if (raw_len != 152 || file.size() != expected_size)
      return std::nullopt;
    const auto checksum = sha256(file.first(file.size() - 32));
    if (!std::equal(checksum.begin(), checksum.end(), file.end() - 32))
      return std::nullopt;
    Receipt receipt;
    receipt.raw_transcript.assign(file.begin() + 16,
                                  file.begin() + 16 + raw_len);
    if (!parse_transcript(receipt.raw_transcript))
      return std::nullopt;
    std::size_t off = 16 + raw_len;
    for (auto &seal : receipt.seals) {
      std::copy_n(file.begin() + off, 32, seal.begin());
      off += 32;
    }
    std::copy_n(file.begin() + off, 32, receipt.program_checksum.begin());
    return receipt;
  } catch (...) {
    return std::nullopt;
  }
}

Bytes derive_flag_key(std::span<const std::uint8_t> raw_transcript,
                      const std::array<Digest, 3> &seals,
                      std::span<const std::uint8_t> salt) {
  Bytes ikm(raw_transcript.begin(), raw_transcript.end());
  for (const auto &seal : seals)
    append(ikm, seal);
  return hkdf_sha256(ikm, salt, "phantom-frame-v1", 32);
}

Bytes encode_encrypted_flag(std::span<const std::uint8_t> plaintext,
                            std::span<const std::uint8_t> key,
                            std::span<const std::uint8_t> salt,
                            std::span<const std::uint8_t> nonce) {
  if (salt.size() != 32 || nonce.size() != 24)
    throw std::runtime_error("flag parameters");
  Bytes header{'P', 'F', 'E', 'N'};
  put_u16(header, 1);
  put_u16(header, 0);
  put_u32(header, static_cast<std::uint32_t>(plaintext.size() + 16));
  put_u32(header, 0);
  append(header, salt);
  append(header, nonce);
  const auto encrypted =
      xchacha20poly1305_encrypt(plaintext, key, nonce, header);
  Bytes out = header;
  append(out, encrypted);
  return out;
}

std::optional<EncryptedFlag>
parse_encrypted_flag(std::span<const std::uint8_t> file) {
  try {
    if (file.size() < 72 + 16 ||
        !std::equal(file.begin(), file.begin() + 4,
                    std::array<std::uint8_t, 4>{'P', 'F', 'E', 'N'}.begin()) ||
        get_u16(file, 4) != 1 || get_u16(file, 6) != 0 ||
        get_u32(file, 12) != 0)
      return std::nullopt;
    const auto n = get_u32(file, 8);
    if (n < 16 || file.size() != 72ull + n)
      return std::nullopt;
    EncryptedFlag flag;
    std::copy_n(file.begin() + 16, 32, flag.salt.begin());
    std::copy_n(file.begin() + 48, 24, flag.nonce.begin());
    flag.aad.assign(file.begin(), file.begin() + 72);
    flag.ciphertext_and_tag.assign(file.begin() + 72, file.end());
    return flag;
  } catch (...) {
    return std::nullopt;
  }
}

std::filesystem::path executable_directory() {
  std::array<char, 4096> path{};
  const auto n = readlink("/proc/self/exe", path.data(), path.size() - 1);
  if (n <= 0)
    return std::filesystem::current_path();
  path[n] = 0;
  return std::filesystem::path(path.data()).parent_path();
}

} // namespace pf
