//
//  SSLCertificateRevokeList.swift
//
//
//  Created by Onno van Zinderen Bakker on 24/06/2024.
//

@_implementationOnly import CNIOBoringSSL
@_implementationOnly import CNIOBoringSSLShims
import NIOCore

#if canImport(Darwin)
import Darwin.C
#elseif canImport(Musl)
import Musl
#elseif os(Linux) || os(FreeBSD) || os(Android)
import Glibc
#else
#error("unsupported os")
#endif

#if canImport(Darwin)
import struct Darwin.time_t
#elseif canImport(Glibc)
import struct Glibc.time_t
#endif



public enum CRLError: Error {
    case failedToLoadCRL
}

extension CRLError: Equatable {}


public final class CertificateRevokeList {
    @usableFromInline
    internal let _ref: OpaquePointer/*<X509_CRL>*/

    @inlinable
    internal func withUnsafeMutableX509CRLPointer<ResultType>(_ body: (OpaquePointer) throws -> ResultType) rethrows -> ResultType {
        return try body(self._ref)
    }

    // Internal to this class we can just access the ref directly.
    private var ref: OpaquePointer {
        return self._ref
    }


    private init(withOwnedReference ref: OpaquePointer) {
        self._ref = ref
    }


    public convenience init(file: String, format: NIOSSLSerializationFormats) throws {
        let fileObject = try Posix.fopen(file: file, mode: "rb")
        defer {
            fclose(fileObject)
        }

        let crl: OpaquePointer?
        switch format {
        case .pem:
            crl = CNIOBoringSSL_PEM_read_X509_CRL(fileObject, nil, nil, nil)
        case .der:
            crl = CNIOBoringSSL_d2i_X509_CRL_fp(fileObject, nil)
        }

        if crl == nil {
            throw NIOSSLError.failedToLoadCertificate
        }

        self.init(withOwnedReference: crl!)
    }


    public convenience init(bytes: [UInt8], format: NIOSSLSerializationFormats) throws {
        let ref = bytes.withUnsafeBytes { (ptr) -> OpaquePointer? in
            let bio = CNIOBoringSSL_BIO_new_mem_buf(ptr.baseAddress, ptr.count)!

            defer {
                CNIOBoringSSL_BIO_free(bio)
            }

            switch format {
            case .pem:
                return CNIOBoringSSL_PEM_read_bio_X509_CRL(bio, nil, nil, nil)
            case .der:
                return CNIOBoringSSL_d2i_X509_CRL_bio(bio, nil)
            }
        }

        if ref == nil {
            throw NIOSSLError.failedToLoadCertificate
        }

        self.init(withOwnedReference: ref!)
    }


    internal convenience init(bytes ptr: UnsafeRawBufferPointer, format: NIOSSLSerializationFormats) throws {
        // TODO(cory):
        // The body of this method is exactly identical to the initializer above, except for the "withUnsafeBytes" call.
        // ContiguousBytes would have been the lowest effort way to reduce this duplication, but we can't use it without
        // bringing Foundation in. Probably we should use Sequence where Element == UInt8 and the withUnsafeContiguousBytesIfAvailable
        // method, but that's a much more substantial refactor. Let's do it later.
        let bio = CNIOBoringSSL_BIO_new_mem_buf(ptr.baseAddress, ptr.count)!

        defer {
            CNIOBoringSSL_BIO_free(bio)
        }

        let ref: OpaquePointer?

        switch format {
        case .pem:
            ref = CNIOBoringSSL_PEM_read_bio_X509_CRL(bio, nil, nil, nil)
        case .der:
            ref = CNIOBoringSSL_d2i_X509_CRL_bio(bio, nil)
        }

        if ref == nil {
            throw CRLError.failedToLoadCRL
        }

        self.init(withOwnedReference: ref!)
    }
    

    deinit {
        CNIOBoringSSL_X509_free(ref)
    }
}


// CertificateRevokeList is publicly immutable and we do not internally mutate it after initialisation.
// It is therefore Sendable.
extension CertificateRevokeList: @unchecked Sendable {}


extension CertificateRevokeList: Equatable {
    public static func ==(lhs: CertificateRevokeList, rhs: CertificateRevokeList) -> Bool {
        return CNIOBoringSSL_X509_CRL_cmp(lhs.ref, rhs.ref) == 0
    }
}
