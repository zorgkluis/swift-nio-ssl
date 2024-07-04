//
//  SSLContext+CRL.swift
//
//
//  Created by Onno van Zinderen Bakker on 28/06/2024.
//

import Foundation
import NIOCore
@_implementationOnly import CNIOBoringSSL
@_implementationOnly import CNIOBoringSSLShims

#if canImport(Darwin)
import Darwin.C
#elseif canImport(Musl)
import Musl
#elseif os(Linux) || os(FreeBSD) || os(Android)
import Glibc
#else
#error("unsupported os")
#endif


extension NIOSSLContext {
    internal static func configureCRL(context: OpaquePointer, configuration: TLSConfiguration) {
        guard configuration.crlCheck else { return }
        //guard let crl = configuration.certificateRevokeList else { return }

        let x509_store = CNIOBoringSSL_SSL_CTX_get_cert_store(context)
        /*let rc = crl.withUnsafeMutableX509CRLPointer { ref in
         CNIOBoringSSL_X509_STORE_add_crl(x509_store, ref)
         }
         if 0 == rc {
         // Do not throw exception because we proceed without enabling CRL
         return
         }*/

        CNIOBoringSSL_X509_STORE_set_lookup_crls(x509_store, lookup_crls)
        CNIOBoringSSL_X509_STORE_set_verify_cb(x509_store, verify_cb)
        getCRL = configuration.getCRL

        let trustParams = CNIOBoringSSL_SSL_CTX_get0_param(context)!
        CNIOBoringSSL_X509_VERIFY_PARAM_set_flags(trustParams, CUnsignedLong(X509_V_FLAG_CRL_CHECK))
        if configuration.crlCheckAll {
            CNIOBoringSSL_X509_VERIFY_PARAM_set_flags(trustParams, CUnsignedLong(X509_V_FLAG_CRL_CHECK_ALL))
        }
    }
}


// MARK: - CRL Lookup

public typealias GetCRLCallback = @Sendable (String) throws -> CertificateRevokeList?

fileprivate var getCRL: GetCRLCallback?


fileprivate func verify_cb(preverify_ok: Int32, x509_store_ctx: OpaquePointer?) -> Int32 {
    let error_code = (preverify_ok == 1) ? X509_V_OK : CNIOBoringSSL_X509_STORE_CTX_get_error(x509_store_ctx)
    if (error_code == X509_V_ERR_UNABLE_TO_GET_CRL) {
        return 1
    }
    return preverify_ok
}


fileprivate func lookup_crls(x509_store_ctx: OpaquePointer?, x509_name: OpaquePointer?) -> OpaquePointer? {
    let current_cert = CNIOBoringSSL_X509_STORE_CTX_get_current_cert(x509_store_ctx)
    guard let current_cert else {
        return nil
    }

    let depth = CNIOBoringSSL_X509_STORE_CTX_get_error_depth(x509_store_ctx)
    print("* lookup_crls() called with depth=\(depth)")

    let crl_dist_points = OpaquePointer(
        CNIOBoringSSL_X509_get_ext_d2i(current_cert, NID_crl_distribution_points, nil, nil)
    )
    if crl_dist_points == nil {
        return nil
    }

    let crl_dist_point_count = CNIOBoringSSL_sk_DIST_POINT_num(crl_dist_points)
    for i in 0..<(crl_dist_point_count) {
        let dist_point = CNIOBoringSSL_sk_DIST_POINT_value(crl_dist_points, i)
        guard let crl = download_crl_from_dist_point(dist_point) else {
            continue
        }

        let crls = CNIOBoringSSL_sk_X509_CRL_new_null()
        CNIOBoringSSL_X509_up_ref(crl._ref)
        CNIOBoringSSL_sk_X509_CRL_push(crls, crl._ref)
        return crls
    }

    return nil
}


fileprivate func download_crl_from_dist_point(
    _ dist_point: UnsafeMutablePointer<DIST_POINT>?
) -> CertificateRevokeList?
{
    guard let dist_point_name = dist_point?.pointee.distpoint else {
        return nil
    }
    /* guard dist_point_name.pointee.type != 0 else {
     return nil
     }*/
    guard let general_names = dist_point_name.pointee.name.fullname else {
        return nil
    }


    let general_name_count = CNIOBoringSSL_sk_GENERAL_NAME_num(general_names)
    for i in 0..<general_name_count {
        let general_name = CNIOBoringSSL_sk_GENERAL_NAME_value(general_names, i);
        assert(general_name != nil)

        var general_name_type: Int32 = 0
        let raw_general_name_asn1_string = CNIOBoringSSL_GENERAL_NAME_get0_value(general_name, &general_name_type)
        let general_name_asn1_string = raw_general_name_asn1_string?.assumingMemoryBound(to: ASN1_STRING.self)

        assert(general_name_asn1_string != nil)
        if (general_name_type != GEN_URI) {
            continue
        }

        guard let cStringURL = CNIOBoringSSL_ASN1_STRING_get0_data(general_name_asn1_string) else {
            return nil
        }
        let url = String(cString: cStringURL)

        // Skip non-HTTP URLs.
        if !url.hasPrefix("http://") {
            continue
        }

        print("  Found CRL URL: \(url)")
        if let crl = try? getCRL?(url) {
            print("  Downloaded CRL from \(url)")
            return crl
        } else {
            print("  Failed to download CRL from \(url)")
        }
    }

    return nil
}
