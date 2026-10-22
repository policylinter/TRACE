import unittest
from trace_api.pipeline.vex import _status
class VexVerdictTests(unittest.TestCase):
    def test_uncertainty_and_operator_exclusion_are_not_non_affection(self):
        for finding in ({'verdict':'needs_review','reachability':'unknown'}, {'verdict':'affected','reachability':'unknown'}, {'verdict':'not_affected','reachability':'suppressed'}):
            self.assertEqual(_status(finding),('under_investigation',None))
    def test_evidenced_verdicts_keep_their_meaning(self):
        self.assertEqual(_status({'verdict':'affected','reachability':'reachable'}),('known_affected',None))
        self.assertEqual(_status({'verdict':'not_affected','reachability':'unreachable'})[0],'known_not_affected')
