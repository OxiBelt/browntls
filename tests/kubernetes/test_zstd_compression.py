import unittest

import zstd_compression


class ZstdCompressionHarnessTest(unittest.TestCase):
    def test_authenticated_records_require_observed_zstd_and_data(self):
        output = (
            '{"event":"connection","role":"client","version":"TLSv1_3",'
            '"peer_certificates":1,"zstd_certificate_messages_received":1,'
            '"sent":"zstd service request","received":"tseuqer ecivres dtsz",'
            '"io":"async"}\n')
        zstd_compression.check_exchange(output, "client", "async", "TLSv1_3")

    def test_wrong_compression_configuration_fails_the_case(self):
        output = (
            '{"event":"connection","role":"client","version":"TLSv1_3",'
            '"peer_certificates":1,"zstd_certificate_messages_received":0,'
            '"sent":"zstd service request","received":"tseuqer ecivres dtsz",'
            '"io":"async"}\n')
        with self.assertRaises(RuntimeError):
            zstd_compression.check_exchange(output, "client", "async", "TLSv1_3")

    def test_dtls_case_requires_dtls_13(self):
        output = (
            '{"event":"connection","role":"client","version":"DTLSv1_3",'
            '"peer_certificates":1,"zstd_certificate_messages_received":1,'
            '"sent":"zstd service request","received":"tseuqer ecivres dtsz",'
            '"io":"tokio-dtls"}\n')
        zstd_compression.check_exchange(output, "client", "tokio-dtls", "DTLSv1_3")


if __name__ == "__main__":
    unittest.main()
