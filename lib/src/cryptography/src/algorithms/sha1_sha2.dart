// Copyright 2019-2020 Gohilla Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import 'dart:convert';

import 'package:crypto/crypto.dart' as impl;

import '../../cryptography.dart';

/// _SHA1_, an old cryptographic hash function that's not recommended for new
/// applications.
///
/// In browser, asynchronous methods are able to take advantage of
/// [Web Cryptography API](https://www.w3.org/TR/WebCryptoAPI/), which provides
/// significantly better performance.
/// Otherwise the implementation uses [package:crypto](https://pub.dev/packages/crypto),
/// which is maintained by Google.
///
/// ## Asynchonous usage (recommended)
/// ```
/// import '../cryptography.dart';
///
/// Future<void> main() async {
///   final message = <int>[1,2,3];
///
///   final hash = await sha1.hash(
///     message,
///   );
///
///   print('Hash: ${hash.bytes}');
/// }
/// ```
///
/// ## Synchronous usage
/// ```
/// import '../cryptography.dart';
///
/// void main() {
///   // Create a sink
///   final sink = sha1.newSink();
///
///   // Add any number of chunks
///   sink.add(<int>[1,2,3]);
///   sink.add(<int>[4,5]);
///
///   // Calculate the hash
///   sink.close();
///   final hash = sink.hash;
///
///   print('Hash: ${hash.bytes}');
/// }
/// ```
const HashAlgorithm sha1 = _Sha1();

/// _SHA224_, a function in the SHA2 family of cryptographic hash functions.
///
/// In browser, asynchronous methods are able to take advantage of
/// [Web Cryptography API](https://www.w3.org/TR/WebCryptoAPI/), which provides
/// significantly better performance.
/// Otherwise the implementation uses [package:crypto](https://pub.dev/packages/crypto),
/// which is maintained by Google.
///
/// ## Example: synchronous usage
/// ```
/// import '../cryptography.dart';
///
/// void main() {
///   // Create a sink
///   final sink = sha224.newSink();
///
///   // Add all parts
///   sink.add(<int>[1,2,3]);
///   sink.add(<int>[4,5]);
///
///   // Calculate hash
///   sink.close();
///   final hash = sink.hash;
///
///   print('Hash: ${hash.bytes}');
/// }
/// ```
const HashAlgorithm sha224 = _Sha224();

/// _SHA256_, a function in the SHA2 family of cryptographic hash functions.
///
/// In browser, asynchronous methods are able to take advantage of
/// [Web Cryptography API](https://www.w3.org/TR/WebCryptoAPI/), which provides
/// significantly better performance.
/// Otherwise the implementation uses [package:crypto](https://pub.dev/packages/crypto),
/// which is maintained by Google.
///
/// ## Asynchonous usage (recommended)
/// ```
/// import '../cryptography.dart';
///
/// Future<void> main() async {
///   final message = <int>[1,2,3];
///
///   final hash = await sha256.hash(
///     message,
///   );
///
///   print('Hash: ${hash.bytes}');
/// }
/// ```
///
/// ## Synchronous usage
/// ```
/// import '../cryptography.dart';
///
/// void main() {
///   // Create a sink
///   final sink = sha256.newSink();
///
///   // Add any number of chunks
///   sink.add(<int>[1,2,3]);
///   sink.add(<int>[4,5]);
///
///   // Calculate the hash
///   sink.close();
///   final hash = sink.hash;
///
///   print('Hash: ${hash.bytes}');
/// }
/// ```
const HashAlgorithm sha256 = _Sha256();

/// _SHA385_, a function in the SHA2 family of cryptographic hash functions.
///
/// In browser, asynchronous methods are able to take advantage of
/// [Web Cryptography API](https://www.w3.org/TR/WebCryptoAPI/), which provides
/// significantly better performance.
/// Otherwise the implementation uses [package:crypto](https://pub.dev/packages/crypto),
/// which is maintained by Google.
///
/// ## Asynchonous usage (recommended)
/// ```
/// import '../cryptography.dart';
///
/// Future<void> main() async {
///   final message = <int>[1,2,3];
///
///   final hash = await sha384.hash(
///     message,
///   );
///
///   print('Hash: ${hash.bytes}');
/// }
/// ```
///
/// ## Synchronous usage
/// ```
/// import '../cryptography.dart';
///
/// void main() {
///   // Create a sink
///   final sink = sha384.newSink();
///
///   // Add any number of chunks
///   sink.add(<int>[1,2,3]);
///   sink.add(<int>[4,5]);
///
///   // Calculate the hash
///   sink.close();
///   final hash = sink.hash;
///
///   print('Hash: ${hash.bytes}');
/// }
/// ```
const HashAlgorithm sha384 = _Sha384();

/// _SHA512_, a function in the SHA2 family of cryptographic hash functions.
///
/// In browser, asynchronous methods are able to take advantage of
/// [Web Cryptography API](https://www.w3.org/TR/WebCryptoAPI/), which provides
/// significantly better performance.
/// Otherwise the implementation uses [package:crypto](https://pub.dev/packages/crypto),
/// which is maintained by Google.
///
/// ## Asynchonous usage (recommended)
/// ```
/// import '../cryptography.dart';
///
/// Future<void> main() async {
///   final message = <int>[1,2,3];
///
///   final hash = await sha512.hash(
///     message,
///   );
///
///   print('Hash: ${hash.bytes}');
/// }
/// ```
///
/// ## Synchronous usage
/// ```
/// import '../cryptography.dart';
///
/// void main() {
///   // Create a sink
///   final sink = sha512.newSink();
///
///   // Add any number of chunks
///   sink.add(<int>[1,2,3]);
///   sink.add(<int>[4,5]);
///
///   // Calculate the hash
///   sink.close();
///   final hash = sink.hash;
///
///   print('Hash: ${hash.bytes}');
/// }
/// ```
const HashAlgorithm sha512 = _Sha512();

abstract class _Hash extends HashAlgorithm {
  const _Hash();

  @override
  int get blockLengthInBytes => _impl.blockSize;

  impl.Hash get _impl;

  @override
  Future<Hash> hash(List<int> input) async {
    ArgumentError.checkNotNull(input);
    return super.hash(input);
  }

  @override
  HashSink newSink() {
    final captureSink = _ImplDigestCaptureSink();
    // ignore: close_sinks
    final implSink = _impl.startChunkedConversion(captureSink);
    return _HashSink(
      implSink,
      captureSink,
    );
  }
}

class _HashSink extends HashSink {
  final ByteConversionSink _sink;
  final _ImplDigestCaptureSink _captureSink;

  bool _isClosed = false;

  _HashSink(this._sink, this._captureSink);

  @override
  Hash get hash => _captureSink._result;

  @override
  void add(List<int> chunk) {
    ArgumentError.checkNotNull(chunk);
    if (_isClosed) {
      throw StateError('Already closed');
    }
    _sink.add(chunk);
  }

  @override
  void addSlice(List<int> chunk, int start, int end, bool isLast) {
    ArgumentError.checkNotNull(chunk, 'chunk');
    ArgumentError.checkNotNull(start, 'start');
    ArgumentError.checkNotNull(end, 'end');
    if (_isClosed) {
      throw StateError('Already closed');
    }
    _sink.addSlice(chunk, start, end, isLast);
    if (isLast) {
      close();
    }
  }

  @override
  void close() {
    if (_isClosed) {
      return;
    }
    _isClosed = true;
    _sink.close();
  }
}

class _ImplDigestCaptureSink extends Sink<impl.Digest> {
  late Hash _result;

  _ImplDigestCaptureSink();

  @override
  void add(impl.Digest implDigest) {
    final hash = Hash(implDigest.bytes);
    _result = hash;
  }

  @override
  void close() {}
}

class _Sha1 extends _Hash {
  const _Sha1();

  @override
  int get hashLengthInBytes => 20;

  @override
  String get name => 'sha1';

  @override
  impl.Hash get _impl => impl.sha1;
}

class _Sha224 extends _Hash {
  const _Sha224();

  @override
  int get hashLengthInBytes => 28;

  @override
  String get name => 'sha224';

  @override
  impl.Hash get _impl => impl.sha224;
}

class _Sha256 extends _Hash {
  const _Sha256();

  @override
  int get hashLengthInBytes => 32;

  @override
  String get name => 'sha256';

  @override
  impl.Hash get _impl => impl.sha256;
}

class _Sha384 extends _Hash {
  const _Sha384();

  @override
  int get hashLengthInBytes => 48;

  @override
  String get name => 'sha384';

  @override
  impl.Hash get _impl => impl.sha384;
}

class _Sha512 extends _Hash {
  const _Sha512();

  @override
  int get hashLengthInBytes => 64;

  @override
  String get name => 'sha512';

  @override
  impl.Hash get _impl => impl.sha512;
}
