import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import './api0v2_utils.dart';
import 'package:crypto/crypto.dart';
import 'package:dio/adapter.dart';
import 'package:dio/dio.dart';
import 'package:http/http.dart' as http;
import 'cryptography/cryptography.dart' as cryptography;

enum API0Method { post, get, del, put }

Map typeCryptographyAlgorithmBundle = {
  0: {'keyExchange': 'secp256k1', 'signature': 'ed25519'},
  1: {'keyExchange': 'X25519', 'signature': 'ed25519'}
};

class API0CryptographyAlgorithmBundle {
  late int typeIndex;
  late cryptography.KeyExchangeAlgorithm keyExchangeAlgorithm;
  late cryptography.SignatureAlgorithm signatureAlgorithm;
  late cryptography.Hkdf keyDerivationFunction;
  late cryptography.Cipher rq2Cipher;

  void setAll(
      int typeIndex,
      cryptography.KeyExchangeAlgorithm keyExchangeAlgorithm,
      cryptography.SignatureAlgorithm signatureAlgorithm) {
    this.typeIndex = typeIndex;
    this.keyExchangeAlgorithm = keyExchangeAlgorithm;
    this.signatureAlgorithm = signatureAlgorithm;
    keyDerivationFunction =
        cryptography.Hkdf(cryptography.Hmac(cryptography.sha256));
    rq2Cipher = cryptography.CipherWithAppendedMac(
        cryptography.aesCbc, cryptography.Hmac(cryptography.sha256));
  }

  API0CryptographyAlgorithmBundle(typeIndex) {
    switch (typeIndex) {
      case 1:
        {
          setAll(1, cryptography.x25519, cryptography.ed25519);
        }
        break;
      default:
        {
          throw Exception('NOT_IMPLEMENTED');
        }
    }
  }
}

class API0RequestSecurityParam {
  int typeIndex;
  late Uint8List requestId;
  late Uint8List clientDeviceId;
  late cryptography.KeyPair keyExchangeRequestAKeyPair;
  late cryptography.PublicKey keyExchangeRequestBPublicKey;
  late cryptography.KeyPair keyExchangeResponseAKeyPair;
  late cryptography.PublicKey keyExchangeResponseBPublicKey;
  late cryptography.KeyPair signatureAKeyPair;
  late cryptography.PublicKey signatureBPublicKey;
  late cryptography.SecretKey requestMasterKey;
  late cryptography.SecretKey requestDerivedKey;
  late cryptography.Nonce requestNonce;
  late cryptography.SecretKey responseMasterKey;
  late cryptography.SecretKey responseDerivedKey;
  late cryptography.Nonce responseNonce;

  API0RequestSecurityParam(
      {required this.typeIndex,
      required this.keyExchangeRequestAKeyPair,
      required this.keyExchangeResponseAKeyPair,
      required this.signatureAKeyPair});
}

typedef OnBadCertificate = dynamic Function(
    X509Certificate cert, String host, int port);
typedef OnNoInternetConnection = dynamic Function();

enum API0ResponseDataType { error, noData, rawData, string, map }

class API0Response {
  late API0Error error;
  late String? responseMessage;
  late Map<dynamic, dynamic>? data;
  late dynamic rawData;
  late Map<String, dynamic>? headers;
  late API0ResponseDataType dataType;

  API0Response.ok(
      {String statusCode = "200",
      this.responseMessage = '',
      this.data,
      this.headers,
      this.rawData}) {
    error = API0Error.ok(statusCode: statusCode);
    if (data != null) {
      dataType = API0ResponseDataType.map;
    } else {
      if (responseMessage!.isNotEmpty) {
        dataType = API0ResponseDataType.string;
      } else {
        if (rawData != null) {
          dataType = API0ResponseDataType.rawData;
        } else {
          dataType = API0ResponseDataType.noData;
        }
      }
    }
  }

  API0Response.asError(
      {String statusCode = "UNKNOWN",
      String reasonCode = "UNKNOWN",
      String messageText = "UNKNOWN",
      dynamic data}) {
    error = API0Error(
        statusCode: statusCode,
        reasonCode: reasonCode,
        messageText: messageText,
        data: data);
    responseMessage = null;
    dataType = API0ResponseDataType.error;
  }

  @override
  String toString() {
    return '{error: $error, response_message: "$responseMessage"}';
  }
}

class API0Network {
  static bool kProfileMode = bool.fromEnvironment('dart.vm.profile');
  static bool kReleaseMode = bool.fromEnvironment('dart.vm.product');
  static bool kDebugMode = !kReleaseMode && !kProfileMode;
  static bool kIsWeb = identical(0, 0.0);

  static bool isDevelopment = false;
  static bool logDioRequestResponse = false;
  static int counterApiRequestIndex = 0;

  static Map config = {
    'BE': "",
    'type': 1, // 0: unprotected  1: protected
    'clientDeviceId': 'device-0001',
    'url': 'http://localhost',
    'url_product': 'http://localhost',
    'is_demo': '0',
    'url_cc': 'http://localhost',
    'url_staging': 'http://localhost',
    'url_step_1': '/01',
    'url_step_2': '/02',
    'fingerprints': [
      'b6b9a6af3e866cbe0e6a307e7dda173b372b2d3ac3f06af15f97718773848008',
      '9aed33c4b87ed95ada957b9d62d7e1f0c2ef9b4d9a8c50954a8a03d6a0f05419'
    ],
    'fingerprints2': [
      'b6b9a6af3e866cbe0e6a307e7dda173b372b2d3ac3f06af15f97718773848008',
      '9aed33c4b87ed95ada957b9d62d7e1f0c2ef9b4d9a8c50954a8a03d6a0f05419'
    ]
  };

  static OnBadCertificate? onBadCertificate;
  static OnNoInternetConnection? onNoInternetConnection;

  static Future<void> checkInternetConnection() async {
    try {
      Uri u = Uri.parse(config['url']);
      final result = await InternetAddress.lookup(u.host);
      if (result.isNotEmpty && result[0].rawAddress.isNotEmpty) {
        return;
      }
    } on SocketException catch (_) {
      if (onNoInternetConnection != null) {
        onNoInternetConnection!();
      } else {
        throw Exception('NO_INTERNET_CONNECTION');
      }
    }
  }

  static Dio createHttpClientSession() {
    Dio dioSession = Dio();
    dioSession.options.connectTimeout = 120000;
    dioSession.options.receiveTimeout = 120000;
    if (isDevelopment) {
      if (logDioRequestResponse) {
        dioSession.interceptors.add(LogInterceptor(
          responseBody: true,
          error: true,
          requestHeader: true,
          responseHeader: true,
          request: true,
          requestBody: true,
        ));
      }
    }
    dioSession.httpClientAdapter = DefaultHttpClientAdapter();
    //if (kIsWeb) return dioSession;

    (dioSession.httpClientAdapter as DefaultHttpClientAdapter)
        .onHttpClientCreate = (client) {
      SecurityContext sc = SecurityContext(withTrustedRoots: true);
      HttpClient httpClient = HttpClient(context: sc);
      httpClient.maxConnectionsPerHost = 5;
      httpClient.badCertificateCallback =
          (X509Certificate cert, String host, int port) {
        Digest certificateDigest = sha256.convert(cert.der);
        for (var fingerprint in config['fingerprints']) {
          if (fingerprint.toLowerCase() == certificateDigest.toString()) {
            return true;
          }
        }
        for (var fingerprint in config['fingerprints2']) {
          if (fingerprint.toLowerCase() == certificateDigest.toString()) {
            return true;
          }
        }
        if (onBadCertificate != null) onBadCertificate!(cert, host, port);
        return false;
      };
      return httpClient;
    };

    return dioSession;
  }

  // ignore: unused_element
  static Future<API0Response> _unprotectedApiWeb(
    API0Method method,
    String url, {
    Object? bodyAsObject,
    Map<String, String>? headers,
  }) async {
    try {
      String fullUrl = joinUrl(config["url"], url);
      //String fullUrl = config["url"] + url;
      var urlObject = Uri.parse(fullUrl);
      late http.Response r1;
      try {
        switch (method) {
          case API0Method.del:
            r1 = await http.delete(urlObject,
                headers: headers, body: bodyAsObject);
            break;
          case API0Method.put:
            r1 =
                await http.put(urlObject, headers: headers, body: bodyAsObject);
            break;
          case API0Method.post:
            //headers ??= {};
            //headers["Content-Type"] = "application/json";
            r1 = await http.post(urlObject,
                headers: headers, body: bodyAsObject);
            break;
          case API0Method.get:
            r1 = await http.get(urlObject, headers: headers);
            break;
          default:
            throw Exception("API0Method not implemented");
        }
      } on http.ClientException catch (e) {
        return API0Response.asError(
            reasonCode: e.message.toString(),
            messageText: e.message.toString(),
            data: e.message);
      } on Exception catch (e) {
        return API0Response.asError(
            reasonCode: e.toString(),
            messageText: e.toString(),
            data: e.toString());
      }
      if ((r1.statusCode < 200) || (r1.statusCode > 299)) {
        return API0Response.asError(
            statusCode: r1.statusCode.toString(),
            reasonCode: r1.statusCode.toString(),
            messageText: r1.body);
      }
      if (r1.headers["content-type"]!.contains("application/json")) {
        dynamic data = jsonDecode(r1.body);
        return API0Response.ok(
            statusCode: r1.statusCode.toString(),
            data: data,
            headers: r1.headers);
      }
      if (r1.headers["content-type"]!.contains("application/hal+json")) {
        String s = utf8.decode(r1.bodyBytes);
        dynamic data = jsonDecode(s);
        return API0Response.ok(
            statusCode: r1.statusCode.toString(),
            data: data,
            headers: r1.headers);
      }
      if (r1.headers['content-type']!.contains("text")) {
        return API0Response.ok(
            statusCode: r1.statusCode.toString(),
            responseMessage: r1.body,
            headers: r1.headers);
      }
      return API0Response.ok(
          statusCode: r1.statusCode.toString(),
          rawData: r1.bodyBytes,
          headers: r1.headers);
    } catch (e) {
      return API0Response.asError(
          reasonCode: e.toString(), messageText: e.toString());
    }
  }

  static String joinUrl(String url1, url2) {
    String frontUrl = url1;
    if (frontUrl.endsWith('/')) {
      frontUrl = frontUrl.substring(0, frontUrl.length - 1);
    }
    String backUrl = url2;
    if (backUrl.startsWith('/')) {
      backUrl = backUrl.substring(1);
    }
    String fullUrl = '$frontUrl/$backUrl';
    return fullUrl;
  }

  static Future<API0Response> unprotectedApi(API0Method method, String url,
      {Object? bodyAsObject, Map<String, String>? headers}) async {
    try {
      String fullUrl = joinUrl(config["url"], url);
      Dio dioSession = createHttpClientSession();
      late Response r1;
      try {
        switch (method) {
          case API0Method.del:
            r1 = await dioSession.delete(fullUrl,
                data: bodyAsObject, options: Options(headers: headers));
            break;
          case API0Method.put:
            r1 = await dioSession.put(fullUrl,
                data: bodyAsObject, options: Options(headers: headers));
            break;
          case API0Method.post:
            r1 = await dioSession.post(fullUrl,
                data: bodyAsObject, options: Options(headers: headers));
            break;
          case API0Method.get:
            r1 = await dioSession.get(fullUrl,
                options: Options(headers: headers));
            break;
          default:
            throw Exception("API0Method not implemented");
        }
      } catch (e) {
        if (e is DioError) {
          if (e.response != null) {
            return API0Response.asError(
                reasonCode: e.response!.statusCode.toString(),
                messageText:
                    e.response!.statusMessage ?? "ERROR-NO_STATUS_MESSAGE",
                data: e.response!.data);
          }
          if (e.error != null) {
            return API0Response.asError(
                reasonCode: e.error!.toString(),
                messageText: e.error!.toString());
          }
        }
      }
      if ((r1.statusCode! < 200) || (r1.statusCode! > 299)) {
        return API0Response.asError(
            statusCode: r1.statusCode.toString(),
            reasonCode: r1.statusCode.toString(),
            messageText: r1.statusMessage ?? "ERROR-NO_STATUS_MESSAGE");
      }
      if (r1.data is Map) {
        return API0Response.ok(
            statusCode: r1.statusCode.toString(),
            data: r1.data,
            headers: r1.headers.map);
      } else {
        if (r1.data is String) {
          return API0Response.ok(
              statusCode: r1.statusCode.toString(),
              responseMessage: r1.data,
              headers: r1.headers.map);
        } else {
          return API0Response.ok(
              statusCode: r1.statusCode.toString(),
              rawData: r1.data,
              headers: r1.headers.map);
        }
      }
    } catch (e) {
      return API0Response.asError(
          reasonCode: e.toString(), messageText: e.toString());
    }
  }

  static Future<API0Response> apiJSON(
    API0Method method,
    String url,
    Map<String, dynamic> params, {
    Map<String, String>? headers,
    Interceptor? interceptor,
  }) async {
    return api(
      method,
      url,
      bodyAsObject: jsonEncode(params),
      headers: headers,
      interceptor: interceptor,
    );
  }

  static printLogCall(int apiRequestIndex, int type, API0Method method,
      String url, String paramsAsString,
      {Map<String, String>? headers}) {
    if (!kReleaseMode) {
      print(
          "\n\n$apiRequestIndex api0.api call: $type, $method, $url\n--Params start--\n$paramsAsString\n--Params end--\n--Headers start--\n"
          "${headers.toString()}\n--Headers end--\n");
    }
  }

  static printLogResult(int apiRequestIndex, API0Response r) {
    if (!kReleaseMode) {
      print("\n\n$apiRequestIndex api0.api response: ${r.toString()}\n\n");
    }
  }

  static Future<API0Response> api(
    API0Method method,
    String url, {
    Object? bodyAsObject,
    Map<String, String>? headers,
    Interceptor? interceptor,
  }) async {
    assert(isDevelopment = true);
    var apiRequestIndex = counterApiRequestIndex++;
    var t = config['type'];
    printLogCall(apiRequestIndex, t, method, url, bodyAsObject.toString(),
        headers: headers);

    try {
      await checkInternetConnection();
      if (t == 0) {
        API0Response r = await unprotectedApi(method, url,
            bodyAsObject: bodyAsObject, headers: headers);
        printLogResult(apiRequestIndex, r);
        return r;
      }
      API0CryptographyAlgorithmBundle c;
      try {
        c = API0CryptographyAlgorithmBundle(t);
      } catch (e) {
        API0Response r =
            API0Response.asError(reasonCode: 'INVALID_REQUEST_CONNECTION_TYPE');
        printLogResult(apiRequestIndex, r);
        return r;
      }

      API0RequestSecurityParam rsp = API0RequestSecurityParam(
          typeIndex: t,
          keyExchangeRequestAKeyPair: await c.keyExchangeAlgorithm.newKeyPair(),
          keyExchangeResponseAKeyPair:
              await c.keyExchangeAlgorithm.newKeyPair(),
          signatureAKeyPair: await c.signatureAlgorithm.newKeyPair());

      switch (method) {
        case API0Method.del:
          url = "${url}d";
          break;
        case API0Method.put:
          url = "${url}t";
          break;
        case API0Method.post:
          url = "${url}p";
          break;
        case API0Method.get:
        default:
          url = "${url}g";
          break;
      }

      // String url01 = config["url"] + config['url_step_1'];
      String url01 = joinUrl(config["url"], config['url_step_1']);

      Uint8List urlAsBytes = utf8.encode(url) as Uint8List;

      Dio dioSession = createHttpClientSession();

      if (interceptor != null) {
        dioSession.interceptors.add(interceptor);
      }

      Uint8List q1StepRequestType =
          vTol32v(Uint8List.fromList([1, config['type']]));
      List<int> q1PackedData = q1StepRequestType +
          vTol32v(rsp.keyExchangeRequestAKeyPair.publicKey.bytes as Uint8List) +
          vTol32v(
              rsp.keyExchangeResponseAKeyPair.publicKey.bytes as Uint8List) +
          vTol32v(rsp.signatureAKeyPair.publicKey.bytes as Uint8List) +
          vTol32v(urlAsBytes);
      Response r1;
      try {
        print('Preparing step 01 for request $url');
        r1 = await dioSession
            .post(url01, data: {'data': base64Encode(q1PackedData)});
        print('Done step 01 for request $url');
      } catch (e) {
        print('Error step 01 $e');
        if (e is DioError) {
          if (e.type != DioErrorType.other) {
            if (e.response != null) {
              if (e.response!.statusCode != null) {
                API0Response r = API0Response.asError(
                    statusCode: e.response!.statusCode.toString(),
                    reasonCode: e.response!.statusCode.toString(),
                    messageText:
                        e.response!.statusMessage ?? "ERROR-NO_STATUS_MESSAGE",
                    data: e.response!.data);
                printLogResult(apiRequestIndex, r);
                return r;
              }
            }
          }

          if (e.error != null) {
            if (e.error is String) {
              API0Response r = API0Response.asError(
                  reasonCode: e.error, messageText: e.error);
              printLogResult(apiRequestIndex, r);
              return r;
            }
            if (e.error.osError != null) {
              API0Response r = API0Response.asError(
                  reasonCode: e.error.osError.errorCode.toString(),
                  messageText: e.error.osError.message);
              printLogResult(apiRequestIndex, r);
              return r;
            }
            API0Response r = API0Response.asError(
                reasonCode: e.error.toString(),
                messageText: e.error.toString());
            printLogResult(apiRequestIndex, r);
            return r;
          }
        }
        API0Response r = API0Response.asError(
            reasonCode: e.toString(), messageText: e.toString());
        printLogResult(apiRequestIndex, r);
        return r;
      }

      if (r1.data['code'] == "FAIL") {
        API0Response r = API0Response.asError(
            reasonCode: r1.data['reasonCode'],
            messageText: r1.data['messageText']);
        printLogResult(apiRequestIndex, r);
        return r;
      }
      String r1PackedDataAsBase64String = r1.data['data'];
      Uint8List r1PackedDataAsBytes = base64Decode(r1PackedDataAsBase64String);

      CursorIterator r1Cursor = CursorIterator();
      Uint8List r1SignatureBPublicKey =
          l32vTov(r1PackedDataAsBytes, cursor: r1Cursor);
      Uint8List r1RequestTimeInMsEpochAsBytes =
          l32vTov(r1PackedDataAsBytes, cursor: r1Cursor);
      Uint8List r1RequestBPublicKey =
          l32vTov(r1PackedDataAsBytes, cursor: r1Cursor);
      Uint8List r1ResponseBPublicKey =
          l32vTov(r1PackedDataAsBytes, cursor: r1Cursor);
      Uint8List r1RequestId = l32vTov(r1PackedDataAsBytes, cursor: r1Cursor);

      // int r1RequestTimeInMsEpoch = bytesToUInt64(r1RequestTimeInMsEpochAsBytes);
      // int r1RequestDurationInMs = DateTime.now().millisecondsSinceEpoch - r1RequestTimeInMsEpoch + 2000;
      // if ((0 > r1RequestDurationInMs) || (r1RequestDurationInMs > 5000)) throw Exception('R1_INVALID_TIMESTAMP');

      rsp.requestId = r1RequestId;
      rsp.keyExchangeRequestBPublicKey =
          cryptography.PublicKey(r1RequestBPublicKey);
      rsp.keyExchangeResponseBPublicKey =
          cryptography.PublicKey(r1ResponseBPublicKey);
      rsp.signatureBPublicKey = cryptography.PublicKey(r1SignatureBPublicKey);

      rsp.requestMasterKey = await c.keyExchangeAlgorithm.sharedSecret(
        localPrivateKey: rsp.keyExchangeRequestAKeyPair.privateKey,
        remotePublicKey: rsp.keyExchangeRequestBPublicKey,
      );
      rsp.requestDerivedKey = await c.keyDerivationFunction
          .deriveKey(rsp.requestMasterKey, outputLength: 32);

      rsp.responseMasterKey = await c.keyExchangeAlgorithm.sharedSecret(
        localPrivateKey: rsp.keyExchangeResponseAKeyPair.privateKey,
        remotePublicKey: rsp.keyExchangeResponseBPublicKey,
      );
      rsp.responseDerivedKey = await c.keyDerivationFunction
          .deriveKey(rsp.responseMasterKey, outputLength: 32);

      cryptography.Cipher cipher = c.rq2Cipher;

      Uint8List headerAsBytes = mapToBytes<String, String>(headers);
      rsp.requestNonce = cipher.newNonce()!;
      Uint8List paramsAsBytes =
          utf8.encode(bodyAsObject!.toString()) as Uint8List;
      List<int> packedParamAsBytes =
          vTol32v(utf8.encode(config['clientDeviceId']) as Uint8List) +
              vTol32v(paramsAsBytes) +
              vTol32v(headerAsBytes);
      Uint8List q2EncryptedRequestMessageAsBytes = await cipher.encrypt(
          packedParamAsBytes,
          secretKey: rsp.requestDerivedKey,
          nonce: rsp.requestNonce);

      int q2EncryptedResponseMessageMaxIndex =
          q2EncryptedRequestMessageAsBytes.length;
      int q2l = q2EncryptedResponseMessageMaxIndex;
      if (q2l > 412) {
        q2l = 412;
      }

      List<int> q2DataToSign = utf8.encode(config['clientDeviceId']) +
          utf8.encode(base64Encode(r1RequestTimeInMsEpochAsBytes)) +
          r1RequestId +
          q2EncryptedRequestMessageAsBytes.sublist(0, q2l) +
          q2EncryptedRequestMessageAsBytes.sublist(
              q2EncryptedResponseMessageMaxIndex - q2l,
              q2EncryptedResponseMessageMaxIndex) +
          rsp.requestNonce.bytes;

      cryptography.Signature q2RequestSignature =
          await c.signatureAlgorithm.sign(q2DataToSign, rsp.signatureAKeyPair);

      //String url02 = config["url"] + config['url_step_2'];
      String url02 = joinUrl(config["url"], config['url_step_2']);

      Uint8List q2StepRequestType =
          vTol32v(Uint8List.fromList([2, config['type']]));
      List<int> q2PackedData = q2StepRequestType +
          vTol32v(rsp.requestId) +
          vTol32v(rsp.requestNonce.bytes as Uint8List) +
          vTol32v(q2EncryptedRequestMessageAsBytes) +
          vTol32v(q2RequestSignature.bytes as Uint8List);
      Response r2;
      try {
        print('Preparing step 02 for request $url');
        r2 = await dioSession
            .post(url02, data: {'data': base64Encode(q2PackedData)});
        print('Done step 02 for request $url');
      } catch (e) {
        print('Error step 02 $e');
        if (e is DioError) {
          if (e.type != DioErrorType.other) {
            if (e.response != null) {
              if (e.response!.statusCode != null) {
                API0Response r = API0Response.asError(
                    statusCode: e.response!.statusCode.toString(),
                    reasonCode: e.response!.statusCode.toString(),
                    messageText:
                        e.response!.statusMessage ?? "ERROR-NO_STATUS_MESSAGE",
                    data: e.response!.data);
                printLogResult(apiRequestIndex, r);
                return r;
              }
            }
          }

          if (e.error != null) {
            if (e.error is String) {
              API0Response r = API0Response.asError(
                  reasonCode: e.error, messageText: e.error);
              printLogResult(apiRequestIndex, r);
              return r;
            }
            if (e.error.osError != null) {
              API0Response r = API0Response.asError(
                  reasonCode: e.error.osError.errorCode.toString(),
                  messageText: e.error.osError.message);
              printLogResult(apiRequestIndex, r);
              return r;
            }
            API0Response r = API0Response.asError(
                reasonCode: e.error.toString(),
                messageText: e.error.toString());
            printLogResult(apiRequestIndex, r);
            return r;
          }
        }
        API0Response r = API0Response.asError(
            reasonCode: e.toString(), messageText: e.toString());
        printLogResult(apiRequestIndex, r);
        return r;
      }

      if (r2.statusCode != 200) {
        API0Response r = API0Response.asError(
            reasonCode: r2.statusCode.toString(),
            messageText: r2.statusMessage ?? "ERROR-NO_STATUS_MESSAGE");
        printLogResult(apiRequestIndex, r);
        return r;
      }
      if (r2.data['code'] == 'FAIL') {
        API0Response r = API0Response.asError(
            reasonCode: r2.data['reasonCode'],
            messageText: r2.data['messageText']);
        printLogResult(apiRequestIndex, r);
        return r;
      }
      String r2packedDataAsBase64String = r2.data['data'];
      Uint8List r2packedDataAsBytes = base64Decode(r2packedDataAsBase64String);

      CursorIterator r2Cursor = CursorIterator();
      Uint8List r2RequestId = l32vTov(r2packedDataAsBytes, cursor: r2Cursor);
      l32vTov(r2packedDataAsBytes,
          cursor:
              r2Cursor); // Uint8List r2RequestTimeInMsEpochAsBytes = l32vTov(r2packedDataAsBytes, cursor: r2Cursor);
      Uint8List r2ResponseNonce =
          l32vTov(r2packedDataAsBytes, cursor: r2Cursor);
      Uint8List r2ResponseSignature =
          l32vTov(r2packedDataAsBytes, cursor: r2Cursor);
      Uint8List r2EncryptedResponseMessageAsBytes =
          l32vTov(r2packedDataAsBytes, cursor: r2Cursor);

      // int r2RequestTimeInMsEpoch = bytesToUInt64(r2RequestTimeInMsEpochAsBytes);
      // int r2RequestDuration = DateTime.now().millisecondsSinceEpoch - r2RequestTimeInMsEpoch + 2000;
      // if ((0 > r2RequestDuration) || (r2RequestDuration > 5000)) throw Exception('R2_INVALID_TIMESTAMP');

      // int r2r1DurationInMs = r2RequestTimeInMsEpoch - r1RequestTimeInMsEpoch + 2000;
      // if ((0 > r2r1DurationInMs) || (r2r1DurationInMs > 5000)) throw Exception('R1_R2_INVALID_REQUEST_DURATION');

      rsp.responseNonce = cryptography.Nonce(r2ResponseNonce);

      if (base64Encode(rsp.requestId) != base64Encode(r2RequestId)) {
        throw Exception('R2_INVALID_REQUEST_ID');
      }

      Uint8List r2DecryptedResponseMessageAsBytes = await cipher.decrypt(
          r2EncryptedResponseMessageAsBytes,
          secretKey: rsp.responseDerivedKey,
          nonce: rsp.responseNonce);
      CursorIterator r3Cursor = CursorIterator();
      Uint8List r2ResponseMessageAsBytes =
          l32vTov(r2DecryptedResponseMessageAsBytes, cursor: r3Cursor);
      Uint8List r2ResponseHeaderAsBytes =
          l32vTov(r2DecryptedResponseMessageAsBytes, cursor: r3Cursor);

      Map<String, dynamic> r2ResponseHeader =
          bytesToHashMap(r2ResponseHeaderAsBytes);

      String r2DecryptedResponseMessageAsString =
          utf8.decode(r2ResponseMessageAsBytes, allowMalformed: true);
      Map<String, dynamic> responseMessageAsJSON =
          jsonDecode(r2DecryptedResponseMessageAsString);

      int r2EncryptedResponseMessageMaxIndex =
          r2EncryptedResponseMessageAsBytes.length;
      int l = r2EncryptedResponseMessageMaxIndex;
      if (l > 512) {
        l = 512;
      }
      List<int> r2DataToSign = r2RequestId +
          rsp.requestNonce.bytes +
          r2ResponseNonce +
          r2EncryptedResponseMessageAsBytes.sublist(0, l) +
          r2EncryptedResponseMessageAsBytes.sublist(
              r2EncryptedResponseMessageMaxIndex - l,
              r2EncryptedResponseMessageMaxIndex);

      cryptography.Signature r2CalcSignature = cryptography.Signature(
          r2ResponseSignature,
          publicKey: rsp.signatureBPublicKey);
      bool r2IsVerified =
          await c.signatureAlgorithm.verify(r2DataToSign, r2CalcSignature);
      if (!r2IsVerified) {
        throw Exception("R2_INVALID_SIGNATURE");
      }
      String s = r2DecryptedResponseMessageAsString;
      API0Response r = API0Response.ok(
          responseMessage: s,
          data: responseMessageAsJSON,
          headers: r2ResponseHeader);
      printLogResult(apiRequestIndex, r);
      return r;
    } catch (e) {
      API0Response r = API0Response.asError(
          reasonCode: e.toString(), messageText: e.toString());
      printLogResult(apiRequestIndex, r);
      return r;
    }
  }
}
