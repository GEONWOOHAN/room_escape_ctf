import unittest
import service

class DonorServiceTests(unittest.TestCase):
    def setUp(self):
        self.key=bytes(range(32)); self.epoch=0x12345678; self.route=0x91abcdef; self.order=service.layout(self.epoch)
        self.donors,self.targets,self.decoys=service.active_positions(self.epoch,self.route)
        self.memory=service.fresh_memory(self.key,self.epoch,self.route)
    def decoded(self):
        return tuple(service.xex(self.memory[self.order[i]],self.order[i],self.key,self.epoch,True) for i in self.targets)
    def test_initial_state_is_denied(self): self.assertNotEqual(self.decoded(),service.expected(self.epoch))
    def test_intended_transplant(self):
        for source,target in zip(self.donors,self.targets): self.memory[self.order[target]]=self.memory[self.order[source]]
        self.assertEqual(self.decoded(),service.expected(self.epoch))
    def test_partial_transplant_is_denied(self):
        for source,target in zip(self.donors[:2],self.targets[:2]): self.memory[self.order[target]]=self.memory[self.order[source]]
        self.assertNotEqual(self.decoded(),service.expected(self.epoch))

    def test_first_write_unlocks_only_diagnostics(self):
        source,target=self.donors[0],self.targets[0]
        self.memory[self.order[target]]=self.memory[self.order[source]]
        self.assertEqual(self.decoded()[0],service.expected(self.epoch)[0])
        self.assertNotEqual(self.decoded(),service.expected(self.epoch))

    def test_old_public_one_shot_strategy_is_denied(self):
        donors,targets,_=service.policy_positions(self.epoch)
        for source,target in zip(donors,targets): self.memory[self.order[target]]=self.memory[self.order[source]]
        self.assertNotEqual(self.decoded(),service.expected(self.epoch))
    def test_wrong_class_is_denied(self):
        target=self.targets[0]; wrong=next(i for i in range(service.N) if service.tweak_class(i)!=service.tweak_class(target))
        self.memory[self.order[target]]=self.memory[self.order[wrong]]
        self.assertNotEqual(self.decoded(),service.expected(self.epoch))
    def test_sessions_are_distinct(self):
        self.assertNotEqual(self.memory,service.fresh_memory(bytes(reversed(range(32))),self.epoch+1,self.route+1))

    def test_layout_is_a_class_preserving_permutation(self):
        for epoch in (0, 1, self.epoch, 0xffffffff):
            order = service.layout(epoch)
            self.assertEqual(sorted(order), list(range(service.N)))
            for logical, physical in enumerate(order):
                self.assertEqual(service.tweak_class(logical), service.tweak_class(physical))

    def test_epoch_changes_layout_and_generation(self):
        self.assertNotEqual(service.layout(self.epoch), service.layout(self.epoch + 1))
        self.assertNotEqual(service.policy_positions(self.epoch), service.policy_positions(self.epoch + 1))
        self.assertNotEqual(service.generation(self.epoch), service.generation(self.epoch + 1))

    def test_public_session_values_do_not_expose_raw_state(self):
        self.assertNotEqual(service.session_stamp(self.epoch),self.epoch)
        self.assertNotEqual(service.route_seal(self.epoch,self.route),self.route)
        self.assertEqual((0x9e3779b1*pow(0x9e3779b1,-1,1<<32))&0xffffffff,1)

    def test_route_only_changes_private_policy_positions(self):
        first=service.active_positions(self.epoch,self.route)
        second=service.active_positions(self.epoch,self.route+1)
        for column in range(3): self.assertEqual(first[column][0],second[column][0])
        self.assertNotEqual(tuple(column[1:] for column in first),tuple(column[1:] for column in second))

    def test_policy_positions_are_distinct_and_class_matched(self):
        for donor,target,decoy,group in zip(self.donors,self.targets,self.decoys,service.POLICY_CLASSES):
            self.assertEqual(len({donor,target,decoy}),3)
            self.assertEqual((service.tweak_class(donor),service.tweak_class(target),service.tweak_class(decoy)),(group,group,group))

    def test_policy_vm_programs(self):
        for value in (0,1,self.epoch,0xffffffff):
            direct_class=((value*5)^3^(value>>2))&15
            direct_step=value&0xffffffff
            direct_step^=(direct_step<<7)&0xffffffff
            direct_step^=direct_step>>9
            direct_step^=(direct_step<<13)&0xffffffff
            self.assertEqual(service.vm(service.CLASS_CODE,value),direct_class)
            self.assertEqual(service.vm(service.STEP_CODE,value),direct_step&0xffffffff)
            self.assertEqual(service.vm(service.LAYOUT_SEED_CODE,value),(value^0x6da57c63)&0xffffffff)
            self.assertEqual(service.vm(service.POLICY_SEED_CODE,value),(value^0xc40be191)&0xffffffff)

    def test_reduced_xex_class_creates_only_intended_collisions(self):
        groups={group:[] for group in range(16)}
        for index in range(service.N): groups[service.tweak_class(index)].append(index)
        self.assertTrue(all(len(indices)==4 for indices in groups.values()))
        for indices in groups.values():
            masks={service.tweak(index,self.key,self.epoch) for index in indices}
            self.assertEqual(len(masks),1)
        self.assertEqual(len({service.tweak(index,self.key,self.epoch) for index in range(service.N)}),16)

if __name__=="__main__": unittest.main()
