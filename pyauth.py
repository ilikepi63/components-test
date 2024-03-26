from http_message_signatures.algorithms import RSA_V1_5_SHA256
# from http_message_signatures.exceptions import SigningError
from http_message_signatures.signatures import HTTPMessageSigner, HTTPMessageVerifier
from http_message_signatures.resolvers import HTTPSignatureKeyResolver
import http_sfv
import requests
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key,
)


PRIVATE_PEM = b"""-----BEGIN RSA PRIVATE KEY-----\r\nMIIEowIBAAKCAQEA3DGzdfA8onY6PtCJVsALzuGWkpEqAgonuG/AFu6Uec0D5OO0\r\ng2g9s+v2P0yb0KhsC/qzDKNDjXUo1/HuLOw55H0uXvfqpCH/QGDHFVsbUTb6kyhx\r\n8FPyxBVEnT5C2Iuo6pOOAczWL9L16N7fBQtndGBkPQykVOVO8PjawtdsNgU4LU+p\r\n0g8YNLDTcz7M42fdR1f6WflkNJfFphDneqCqTzCm+mayYtgAHK5fOJv4Gt+Hu9Y/\r\nh6D60SnXk0GMH1I0HQ+JSfCFrWaIX2ff+4ZNR792OvCWyAp62arNv1aXE5zuvdha\r\nWSdJsKLr/L+BZOtVZYVfxgw8uAUexv8RU9J8dwIDAQABAoIBAFf81EVwdgpFTAkF\r\ns5uiqhVFN7Hhp/OgszaUESIYu+Pf9IpmIx/Pa7iVtZSdvDWo12QCDcIjCz9fba68\r\n0fvJeWjATONOFcj4fNLw2RzDhyrw2TgslTr/kKaiCQT8eCGnzRvPUpONkpkRp4oi\r\nZOPTJsfuLJ/oiVITP3QzPNdW1brPpPFYiF0NhKVl8qtyK2DrJUSxwt6kqtZ50B6A\r\nm1tXc4POpEulzTMCNmrgIwhOYwS1D0JgORjG9gPi9G72d6ZzPYzWqUR7R8XN2s9/\r\nDuJh8XiKQcvorQmvygvNuh1wz2t6xZu5b0xYOabAezhGXEb6ZgixNZNp1Y+Fa0UN\r\nQVnxJ0ECgYEA3fEMzKj/pwlWPbCAkj+URp82WY1Oa+3NV7ME5TIbVzvlTGLX37YU\r\nIFJGC1Ucps7DCmzmTFVJnNG2JZB9FFHQnRuOWYRB5uXFDnQAS2VVAjHrbf0P2TBy\r\n1HMK/sLSVnoe+2rOyOPmzrSLuy17z6mcZEpTOhnHJVpFnzNBwIH/t4kCgYEA/fwA\r\nm84/U0Rai5SiPl0RCQgExnNdGn/BfSgt5F7wFXVDODz6Oj9xKOaJMZeMME3ev3lo\r\nMYPoQF6x0zqJmBeJcwgIV1oHfw69vat+bobHQBzKgfHW9LPk4Pq+kB5jrAx4HRmR\r\nJNrN2nFCEO8n9zPfVc1t/W5WmXHlPlS9wu0/k/8CgYA64LnOiX7Y50czsmFJawiA\r\n+7fFZhFJ3Jo/C8TesL5EFCWucAJo3LrWID1owDmLnwpq95zY3z9aFOBHct9bxqCb\r\nLTZEVSvOf2IZhXiWh9lXbbrRQPM1YP71kVd3YmO+gUM624jkDmGqsIbpLxXLb2mH\r\nyZfur+v+4sXZiBWHZnVaUQKBgQDLHI54CxZFRrKKUVD2QoLvEASRl4xrNqPLrSgW\r\nK34gCui4vrr1ferG5KXujN1Fe+CYi0Sx5GUFpTTcUUHb6Wa4IUJaaNr51xYR6mVv\r\nikUplly0UmyuwHZXHO7sXgEjg81CqEGUkY5yFITa+gaiAE+oVGKTe3uxto23rRkc\r\nG5LujQKBgF9FuZkBK2gnOfaVnjKoXQKU8S+iaWuGRYuYYVYkHAY/zihLUgOVicQ4\r\nK+ItUKlVYuNb+xFkiwiTZFPs64xncL40B5kG5j2nsmk2qteGV0e2wQc3DLlBXHnf\r\nziujI3jSSeKbtzdS6HKy5zxXTH2IWkP/th0WrEJvuD9N0xlXJlX/\r\n-----END RSA PRIVATE KEY-----\r\n"""

PUBLIC_PEM = b"""-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEA3DGzdfA8onY6PtCJVsALzuGWkpEqAgonuG/AFu6Uec0D5OO0g2g9
s+v2P0yb0KhsC/qzDKNDjXUo1/HuLOw55H0uXvfqpCH/QGDHFVsbUTb6kyhx8FPy
xBVEnT5C2Iuo6pOOAczWL9L16N7fBQtndGBkPQykVOVO8PjawtdsNgU4LU+p0g8Y
NLDTcz7M42fdR1f6WflkNJfFphDneqCqTzCm+mayYtgAHK5fOJv4Gt+Hu9Y/h6D6
0SnXk0GMH1I0HQ+JSfCFrWaIX2ff+4ZNR792OvCWyAp62arNv1aXE5zuvdhaWSdJ
sKLr/L+BZOtVZYVfxgw8uAUexv8RU9J8dwIDAQAB
-----END RSA PUBLIC KEY-----"""


class RSASignatureKeyResolver(HTTPSignatureKeyResolver):
    def resolve_private_key(self, key_id: str):
        return PRIVATE_PEM

    def resolve_public_key(self, key_id: str):
        return PUBLIC_PEM


def sign_request_with_rsa_tpm_key(
):
    """
    Sign a request to device gateway using the TPM

    Args:
        tpm_device (str): TPM device name
        key_object_handle (str): the TPM hex object handle of the signing key
        key_id (str): an ID to use in the signature for the signing key
        verb (str): HTTP verb of request (POST, PUSH, etc.)
        url (str): the url of HTTP request
        payload (dict): payload of the request to sign
        headers (dict): the HTTP request headers

    Returns:
        requests.PreparedRequest: the signed request object

    """

    request = requests.Request(
        "GET", "http://127.0.0.1/device/bab21e7e-93fc-394f-b433-2392f4bd7188/config")
    request_to_sign = request.prepare()
    # if payload is not None:
    #     payload = farshot.compat.to_byte_string(payload)
    #     request_to_sign.headers['Content-Digest'] = str(
    #         {'sha256': hashlib.sha256(payload).digest()}
    #     )

    signer = HTTPMessageSigner(
        signature_algorithm=RSA_V1_5_SHA256,
        key_resolver=RSASignatureKeyResolver()
    )
    signer.sign(
        request_to_sign,
        key_id="rsa-pss",
        covered_component_ids=('@method', '@path'),
        include_alg=True,
    )

    return request_to_sign
# "signature": "pyhms=:\"19J2rkirlthHReGCX1OaXDMAxZKE8GO4gy5Y+qd7EROa0vLJmzCUWtO1Y0PqZs+3RqRN3Ov/jGWskp/ulmsJ/lnfys58g0jPr1IYtCebC62cUbnRfA8Xu7vWd++bDVM7J0rHJj86ch+NIvjmTTHibJxiRR3eF5naqPsHplWBNoE2Q+SeuwBpCju8+kw5BLq9f/CM0KhwFJIpSKGAcMdwYqLYSbBGO0OgV5oxExEwg67rw63QeGph2dNKD13207X3Wfi9SbUzvfACDz4jGZ65svNhi7GznWueA+xtCO4Soogq1sYIy3vLpus6CrsQS0LpAzLHXO+az+4no6i1truf/A==\":",
#     "signature-input": "pyhms=(\"@path\" \"@method\");alg=rsa-v1_5-sha256;created=1711372056;keyid=\"rsa-pss\"",

# print(sign_request_with_rsa_tpm_key("keyod", "GET", "https://www.device-gatway.com/config", None, []).headers)


def verify_rsa_signature(request: requests.Request) -> bool:
    # request = requests.Request("GET", "http://127.0.0.1/device/bab21e7e-93fc-394f-b433-2392f4bd7188/config", headers={
    # "Signature": "pyhms=:EW2HqOaDOHWHThnTH8lAHeVSNxzA6auM7slNLeXIut4MYzcGyZHqy4Nw5K0E7sIWlVtMbhz2rZk1IF7TxujRmowvmbhMq4DnuTuXHX43gBKTGHCCuBLtGtPX3irhSDH75cLZz+RZWgxiJa0tMPUFayqSzF0Cdn/Lynbnf+E3jLgh0k8egz4uIhIkhzmFwAKS0Y5ckaxSEewOd3bXHj6M+xKHjpZemYAsSKYRQ15TWSsEQ9xQpZEnVMx6Q88LRSTKKwsr3A8rX2DufQMgcPaVszHzOUXQ+rFiBgmo3Aou2d9RXgfMKHczbwzQ/EkuD3rm38+oCyMd3JqZA7S21Ot4DA==:",
    # "Signature-Input": "pyhms=(\"@method\" \"@path\");created=1711392761;keyid=\"rsa-pss\";alg=\"rsa-v1_5-sha256\"",
    #     # "Signature": "pyhms=:\"19J2rkirlthHReGCX1OaXDMAxZKE8GO4gy5Y+qd7EROa0vLJmzCUWtO1Y0PqZs+3RqRN3Ov/jGWskp/ulmsJ/lnfys58g0jPr1IYtCebC62cUbnRfA8Xu7vWd++bDVM7J0rHJj86ch+NIvjmTTHibJxiRR3eF5naqPsHplWBNoE2Q+SeuwBpCju8+kw5BLq9f/CM0KhwFJIpSKGAcMdwYqLYSbBGO0OgV5oxExEwg67rw63QeGph2dNKD13207X3Wfi9SbUzvfACDz4jGZ65svNhi7GznWueA+xtCO4Soogq1sYIy3vLpus6CrsQS0LpAzLHXO+az+4no6i1truf/A==\":",
    #     # "Signature-Input": "pyhms=(\"@path\" \"@method\");alg=rsa-v1_5-sha256;created=1711372056;keyid=\"rsa-pss\""
    # })

    verifier = HTTPMessageVerifier(
        signature_algorithm=RSA_V1_5_SHA256,
        key_resolver=RSASignatureKeyResolver(),
    )

    is_valid = verifier.verify(
        message=request,
    )

    return is_valid


request = sign_request_with_rsa_tpm_key()

# print(request.headers)
# print(request.headers)
# verify_rsa_signature(request=request)

from pprint import pprint as print
public_key = load_pem_public_key(PUBLIC_PEM)

dict_header_node = http_sfv.Dictionary()

dict_header_node.parse(request.headers["Signature"].encode())

dict_header_node.parse("pyhms=:A/KVDogUBT1wYfK7ZIv5g++GWanltTRKxPAvCSn86G65YwAUpb4b0mxvryxRBYjXIuLbXmse6Z3YcklISCIDXu4wtY+CrWYwtnERjh0gNXQdnhu8PPKfrMCv7C3UybbaF+s7TtR14JYsXv7+HdcgEW8Oe/w8jeNHoUhw+JJx+QB2Yi6TMoZk+cfe/P+KEDzSQYmO/Cz5mO7mBJ6oc2a0WFfBbG0hcZToLNBujHFq3DyNT12QlmQPrLOC7FXz3dcpq9YEmMAAHpJL69IaRA1A27tLRdb1rAmJk+9tZa/gjDPEmo/LeyjCNSv3Ks3otMG5SYld8HUHA3Dvn7kZ0pIy1w==:".encode())




padding = padding.PKCS1v15()
hash_algorithm = hashes.SHA256()

# print(public_key.verify(dict_header_node["pyhms"].value, b"hello", padding, hash_algorithm))


## NEW STUFF

request = requests.Request("GET", "http://127.0.0.1/device/bab21e7e-93fc-394f-b433-2392f4bd7188/config", headers={
    "Signature": "pyhms=:XWCAHUBPK1oJN6ACD6j4Em73HQfHDoJW3qjOjImcFUqEk4K2H0274tuAExP1sMI8pxUNFlYPkSIGQEl+MIrLIlqkKBVX0TVmjpLgSNm/5OcetNCRRJvVUPZ6PaE9ZmZYjFI/3VJymZ3B8/fSO459tMOm3hLXhrhSgsdK+Ji1TqTEjOCRt4veZGET7e8LzYPaMOTZxHDd3kyIGw9P14B5WCd5vFUVIcvci/DM/veVfwoQEC0nOtKJZR5RODL4TKj8EesUutTqqAox/cf60FKTFE1fd8r3nJIb/VOcbMeMMQBsYJD3Ov2ybnQZ/+QIrvbp2KvdoAr2NBduNxoCicv89g==:",
    "Signature-Input": "pyhms=(\"@method\" \"@path\");created=1711439481;keyid=\"rsa-pss\";alg=\"rsa-v1_5-sha256\"",
        # "Signature": "pyhms=:\"19J2rkirlthHReGCX1OaXDMAxZKE8GO4gy5Y+qd7EROa0vLJmzCUWtO1Y0PqZs+3RqRN3Ov/jGWskp/ulmsJ/lnfys58g0jPr1IYtCebC62cUbnRfA8Xu7vWd++bDVM7J0rHJj86ch+NIvjmTTHibJxiRR3eF5naqPsHplWBNoE2Q+SeuwBpCju8+kw5BLq9f/CM0KhwFJIpSKGAcMdwYqLYSbBGO0OgV5oxExEwg67rw63QeGph2dNKD13207X3Wfi9SbUzvfACDz4jGZ65svNhi7GznWueA+xtCO4Soogq1sYIy3vLpus6CrsQS0LpAzLHXO+az+4no6i1truf/A==\":",
        # "Signature-Input": "pyhms=(\"@path\" \"@method\");alg=rsa-v1_5-sha256;created=1711372056;keyid=\"rsa-pss\""
})

verify_rsa_signature(request )

verifier = HTTPMessageVerifier(
    signature_algorithm=RSA_V1_5_SHA256,
    key_resolver=RSASignatureKeyResolver(),
)

sig_inputs = verifier._parse_dict_header("Signature-Input", request.headers)
signature = verifier._parse_dict_header("Signature", request.headers)

for label, sig_input in sig_inputs.items():

    sig_base, sig_params_node, sig_elements = verifier._build_signature_base(
        request, covered_component_ids=list(sig_input), signature_params=sig_input.params
    )  

    print(sig_base)
    print(type(sig_base))

    f = open("sigbase.txt", "w")
    f.write(sig_base)
    f.close()

    private_key = load_pem_private_key(PRIVATE_PEM, None)

    public_key.verify(signature["pyhms"].value, sig_base.encode(), padding, hash_algorithm)

        # if len(sig_inputs) != 1:
        #     # TODO: validate all behaviors with multiple signatures
        #     raise InvalidSignature("Multiple signatures are not supported")
        # signature = self._parse_dict_header("Signature", message.headers)
        # verify_results = []
        # for label, sig_input in sig_inputs.items():
        #     self.validate_created_and_expires(sig_input, max_age=max_age)
        #     if label not in signature:
        #         raise InvalidSignature("Signature-Input contains a label not listed in Signature")
        #     if "alg" in sig_input.params:
        #         if sig_input.params["alg"] != self.signature_algorithm.algorithm_id:
        #             raise InvalidSignature("Unexpected algorithm specified in the signature")
        #     key = self.key_resolver.resolve_public_key(sig_input.params["keyid"])
        #     for param in sig_input.params:
        #         if param not in self.signature_metadata_parameters:
        #             raise InvalidSignature(f'Unexpected signature metadata parameter "{param}"')
        #     try:
        #         sig_base, sig_params_node, sig_elements = self._build_signature_base(
        #             message, covered_component_ids=list(sig_input), signature_params=sig_input.params
        #         )
        #     except Exception as e:
        #         raise InvalidSignature(e) from e
        #     verifier = self.signature_algorithm(public_key=key)
        #     raw_signature = signature[label].value
        #     print("RAW_SIGNATURE", sig_base.encode())
        #     try:
        #            verifier.verify(signature=raw_signature, message=sig_base.encode())
        #     except Exception as e:
        #         print("Exception")
        #         print(e)
        #         raise InvalidSignature(e) from e
        #     verify_result = VerifyResult(
        #         label=label,
        #         algorithm=self.signature_algorithm,
        #         covered_components=sig_elements,
        #         parameters=dict(sig_params_node.params),
        #         body=None,
        #     )
        #     verify_results.append(verify_result)
        # return verify_results
