import 'dart:collection';
import 'dart:convert';
import 'dart:typed_data';

class API0Error {
  late String code;
  late String statusCode;
  late String? reasonCode;
  late String? messageText;
  late dynamic data;

  void setAllValue({required String code, required String statusCode, String? reasonCode, String? messageText, dynamic data}) {
    this.code = code;
    this.statusCode = statusCode;
    this.reasonCode = reasonCode;
    if ((messageText == null) && (reasonCode != null)) {
      messageText = reasonCode;
    }
    this.messageText = messageText;
    if (data != null) {
      this.data = data;
    }
  }

  API0Error({String code = 'ERROR', String statusCode = 'UNKNOWN', String reasonCode = 'UNKNOWN', String messageText = 'Unknown error.', dynamic data}) {
    setAllValue(code: code, statusCode: statusCode, reasonCode: reasonCode, messageText: messageText, data: data);
  }

  API0Error.ok({String statusCode = "200"}) {
    setAllValue(code: 'OK', statusCode: statusCode, reasonCode: 'OK', messageText: 'OK');
  }

  @override
  String toString() {
    return '{code: "$code", statusCode: "$statusCode", reasonCode: "$reasonCode", messageText: "$messageText"}';
  }
}

class CursorIterator {
  late int index;

  CursorIterator({int? v}) {
    index = v ?? 0;
  }
}

Uint8List int64toBytes(int u) {
  return Uint8List(8)..buffer.asByteData().setInt64(0, u, Endian.little);
}

Uint8List int32toBytes(int u) {
  return Uint8List(4)..buffer.asByteData().setInt32(0, u, Endian.little);
}

int bytesToUInt64(Uint8List u) {
  ByteData x1 = ByteData.sublistView(u);
  var x2 = x1.getUint64(0, Endian.little);
  return x2;
}

int bytesToInt64(Uint8List u) {
  ByteData x1 = ByteData.sublistView(u);
  var x2 = x1.getInt64(0, Endian.little);
  return x2;
}

int bytesToUInt32(Uint8List u, {int startIndex = 0}) {
  ByteData x1 = ByteData.sublistView(u);
  var x2 = x1.getUint32(startIndex, Endian.little);
  return x2;
}

Uint8List vTol32v(Uint8List v) {
  int l = v.lengthInBytes;
  Uint8List t = int32toBytes(l);
  List<int> o = t + v;
  return Uint8List.fromList(o);
}

Uint8List l32vTov(Uint8List l32v, {CursorIterator? cursor}) {
  int startIndex = cursor?.index ?? 0;
  int l = bytesToUInt32(l32v, startIndex: startIndex);
  Uint8List x = l32v.sublist(startIndex + 4, startIndex + 4 + l);
  if (cursor != null) cursor.index = (startIndex + 4 + l);
  return x;
}

Uint8List mapToBytes<K, V>(Map<K, V>? m) {
  if (m == null) return Uint8List(0);
  List<int> r = vTol32v(int64toBytes(m.length));
  m.forEach((K key, V value) {
    r = r + vTol32v(utf8.encode(key.toString()) as Uint8List);
    r = r + vTol32v(utf8.encode(value.toString()) as Uint8List);
  });
  return Uint8List.fromList(r);
}

Map<String, dynamic> bytesToHashMap(Uint8List b) {
  CursorIterator c = CursorIterator();
  Uint8List lAsBytes = l32vTov(b, cursor: c);
  int l = bytesToInt64(lAsBytes);
  Map<String, String> r = HashMap<String, String>();
  for (int i = 0; i < l; i++) {
    Uint8List k = l32vTov(b, cursor: c);
    String key = utf8.decode(k, allowMalformed: true);
    Uint8List v = l32vTov(b, cursor: c);
    String value = utf8.decode(v, allowMalformed: true);
    r[key] = value;
  }
  return r;
}
