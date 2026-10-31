program jevban_test;

(* Unit checks for jevban: addresses and CIDR, the Apache parser, the
   signatures, and the Jev request/response shapes. Exit code 1 on any
   failure. *)

{$mode objfpc}{$H+}

uses
  SysUtils, Classes, Math, fpjson, jsonparser,
  Ban.Net, Ban.Apache, Ban.Signatures, Ban.Jev, Ban.Local, Ban.Config;

var
  Failures: Integer = 0;
  Checks: Integer = 0;

procedure Check(ACond: Boolean; const AWhat: string);
begin
  Inc(Checks);
  if not ACond then
  begin
    Inc(Failures);
    WriteLn('FAIL: ', AWhat);
  end;
end;

procedure TestNet;
var
  A: TIpAddr;
  C: TCidr;
  L: TCidrList;

  function Canon(const S: string): string;
  var
    LA: TIpAddr;
  begin
    if ParseIp(S, LA) then
      Result := IpToStr(LA)
    else
      Result := '(invalid)';
  end;

begin
  Check(Canon('192.0.2.1') = '192.0.2.1', 'ipv4');
  Check(Canon('::ffff:192.0.2.1') = '192.0.2.1', 'v4-mapped prints as v4');
  Check(Canon('2001:DB8:0:0:0:0:0:1') = '2001:db8::1', 'v6 compress');
  Check(Canon('2001:db8::') = '2001:db8::', 'v6 trailing ::');
  Check(Canon('::1') = '::1', 'v6 loopback');
  Check(Canon('::') = '::', 'v6 any');
  Check(Canon('2001:db8:0:1:0:0:0:1') = '2001:db8:0:1::1', 'v6 longest zero run');
  Check(Canon('[2001:db8::1]') = '2001:db8::1', 'v6 brackets');
  Check(Canon('1:2:3:4:5:6:7:8') = '1:2:3:4:5:6:7:8', 'v6 full');
  Check(Canon('256.1.1.1') = '(invalid)', 'v4 octet range');
  Check(Canon('1.2.3') = '(invalid)', 'v4 short');
  Check(Canon('1.2.3.4; rm -rf /') = '(invalid)', 'shell text rejected');
  Check(Canon('1::2::3') = '(invalid)', 'two ::');
  Check(Canon('1:2:3:4:5:6:7:8:9') = '(invalid)', 'nine groups');
  Check(Canon('example.com') = '(invalid)', 'hostname');
  Check(Canon('$(id)') = '(invalid)', 'command substitution');

  Check(ParseCidr('10.0.0.0/8', C) and ParseIp('10.200.3.4', A) and CidrMatch(C, A), 'v4 cidr in');
  Check(ParseIp('11.0.0.1', A) and not CidrMatch(C, A), 'v4 cidr out');
  Check(ParseCidr('2001:db8::/32', C) and ParseIp('2001:db8:ffff::1', A) and CidrMatch(C, A), 'v6 cidr in');
  Check(ParseIp('2001:db9::1', A) and not CidrMatch(C, A), 'v6 cidr out');
  Check(not ParseCidr('10.0.0.0/33', C), 'v4 prefix range');
  L := ParseCidrList('127.0.0.0/8, ::1 192.168.1.0/24');
  Check(Length(L) = 3, 'cidr list');
  Check(ParseIp('192.168.1.77', A) and InCidrList(L, A), 'in list');
  Check(ParseIp('::1', A) and InCidrList(L, A), 'v6 in list');
  Check(ParseIp('8.8.8.8', A) and not InCidrList(L, A), 'not in list');
end;

procedure TestApache;
var
  E: TAccessEntry;
begin
  Check(ParseAccessLine('203.0.113.66 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif?a=1 HTTP/1.0" 200 2326 "http://www.example.com/start.html" "Mozilla/4.08 [en] (Win98; I ;Nav)"', E), 'combined');
  Check(E.IpText = '203.0.113.66', 'combined ip');
  Check((E.Method = 'GET') and (E.Target = '/apache_pb.gif?a=1') and (E.Protocol = 'HTTP/1.0'), 'request split');
  Check((E.Status = 200) and (E.Bytes = 2326), 'status, bytes');
  Check(E.Agent = 'Mozilla/4.08 [en] (Win98; I ;Nav)', 'agent with brackets');
  Check(E.Referer = 'http://www.example.com/start.html', 'referer');
  Check(E.Epoch = 971211336, 'time with offset -> UTC: ' + IntToStr(E.Epoch));

  Check(ParseAccessLine('127.0.0.1 - - [10/Oct/2000:13:55:36 +0000] "GET / HTTP/1.1" 304 -', E), 'common');
  Check((E.Status = 304) and (E.Bytes = 0) and (E.Agent = ''), 'common fields');

  Check(ParseAccessLine('www.example.com:443 2001:db8::1 - - [10/Oct/2000:13:55:36 +0530] "POST /x HTTP/2.0" 201 5 "-" "ua"', E), 'vhost_combined');
  Check((E.VHost = 'www.example.com:443') and (E.IpText = '2001:db8::1'), 'vhost + v6');
  Check(E.Epoch = 971166336, 'positive offset: ' + IntToStr(E.Epoch));

  Check(ParseAccessLine('192.0.2.66 - - [31/Oct/2026:10:00:11 +0000] "\x16\x03\x01\x02" 400 226 "-" "-"', E), 'binary request');
  Check((E.Method = '') and (E.Target = '\x16\x03\x01\x02'), 'binary request kept whole');
  Check(ParseAccessLine('192.0.2.1 - - [31/Oct/2026:10:00:11 +0000] "GET /a\"b HTTP/1.1" 404 1 "-" "x \"quoted\" y"', E), 'escaped quotes');
  Check(E.Agent = 'x \"quoted\" y', 'agent keeps escapes');
  Check(ParseAccessLine('192.0.2.1 - - [31/Oct/2026:10:00:11 +0000] "GET /%252e%252e/etc/passwd HTTP/1.1" 404 1', E) and
    (E.Decoded = '/../etc/passwd'), 'double url-decoding: ' + E.Decoded);

  Check(not ParseAccessLine('garbage', E), 'garbage');
  Check(not ParseAccessLine('not-an-ip - - [31/Oct/2026:10:00:11 +0000] "GET / HTTP/1.1" 200 1', E), 'hostname client');
  Check(not ParseAccessLine('', E), 'empty');
end;

procedure TestSignatures;
var
  S: TSignatureSet;
  Lines: TStringList;
  E: TAccessEntry;
  Tags: TStringList;
  I, LScore: Integer;
  LExpect: array[0..14] of Integer = (
    0, 0, 0, 0,          { googlebot, a visitor, a 404 }
    10, 10, 6, 6,        { .env, .git, wp-config.php.bak, phpmyadmin }
    10, 10, 20, 10, 6,   { thinkphp, traversal, sqli + sqlmap, jndi, binary }
    10, 3);              { .env from localhost, wp-login }

  function MinScore(AIdx: Integer): Integer;
  begin
    Result := LExpect[AIdx];
  end;

begin
  S := TSignatureSet.Create;
  Lines := TStringList.Create;
  Tags := TStringList.Create;
  try
    Check(S.Count > 20, 'builtin signatures');
    Lines.LoadFromFile(ExtractFilePath(ParamStr(0)) + 'sample_access.log');
    Check(Lines.Count = 15, 'sample lines');
    for I := 0 to Lines.Count - 1 do
    begin
      Check(ParseAccessLine(Lines[I], E), Format('sample %d parses', [I + 1]));
      Tags.Clear;
      LScore := S.Score(E, Tags);
      if MinScore(I) = 0 then
        Check(LScore = 0, Format('sample %d is clean, got %d [%s]', [I + 1, LScore, Tags.CommaText]))
      else
        Check(LScore >= MinScore(I), Format('sample %d scores >= %d, got %d [%s]', [I + 1, MinScore(I),
          LScore, Tags.CommaText]));
    end;
  finally
    Tags.Free;
    Lines.Free;
    S.Free;
  end;
end;

procedure TestSignatureFile;
var
  S: TSignatureSet;
  F: TStringList;
  E: TAccessEntry;
  LPath: string;
begin
  LPath := GetTempFileName;
  F := TStringList.Create;
  try
    F.Add('# custom rules');
    F.Add('10 url secret-admin ^/my-hidden-admin');
    F.Add('');
    F.Add('5	agent bad-bot BadBot/\d');
    F.SaveToFile(LPath);
  finally
    F.Free;
  end;
  S := TSignatureSet.Create(False);
  try
    S.LoadFile(LPath);
    Check(S.Count = 2, 'file rules');
    ParseAccessLine('192.0.2.1 - - [31/Oct/2026:10:00:11 +0000] "GET /my-hidden-admin/x HTTP/1.1" 404 1 "-" "BadBot/2"', E);
    Check(S.Score(E, nil) = 15, 'file rules score');
    ParseAccessLine('192.0.2.1 - - [31/Oct/2026:10:00:11 +0000] "GET /.env HTTP/1.1" 404 1 "-" "x"', E);
    Check(S.Score(E, nil) = 0, 'builtins off');
  finally
    S.Free;
    DeleteFile(LPath);
  end;
end;

procedure TestJev;
var
  J: TJevClient;
  LItems: TList;
  LItem: TJevItem;
  LData: TJSONData;
  LRoot, LQ: TJSONObject;
  LError: string;
  I: Integer;
begin
  J := TJevClient.Create;
  LItems := TList.Create;
  try
    LItem := TJevItem.Create;
    LItem.Ip := '203.0.113.66';
    LItem.Hits := 'env-file,vcs-dir';
    LItem.Flagged.Add('31/Oct/2026:10:00:05 "GET /.env HTTP/1.1" 404 196 ua="x \"y\""');
    LItem.Flagged.Add('31/Oct/2026:10:00:05 "GET /.git/config HTTP/1.1" 404 196 ua="x"');
    LItems.Add(LItem);
    LItem := TJevItem.Create;
    LItem.Ip := '2001:db8::1';
    LItem.Hits := 'wordpress';
    LItem.Flagged.Add('31/Oct/2026:10:00:06 "GET /wp-login.php HTTP/1.1" 200 1 ua="x"');
    LItem.Earlier.Add('31/Oct/2026:10:00:01 "GET / HTTP/1.1" 200 1 ua="x"');
    LItems.Add(LItem);

    LData := GetJSON(J.BuildRequest(LItems));
    try
      LRoot := TJSONObject(LData);
      Check(LRoot.Get('model', '') = 'openjev', 'model');
      Check(LRoot.Objects['state'].Objects['clients'].Count = 2, 'two clients in one state');
      Check(LRoot.Objects['state'].Objects['clients'].Objects['203.0.113.66'].Arrays['flagged_requests'].Count = 2,
        'flagged requests');
      Check(LRoot.Objects['state'].Objects['clients'].Objects['2001:db8::1'].Arrays['other_recent_requests'].Count = 1,
        'other recent requests');
      Check(LRoot.Objects['questions'].Count = 2, 'one question per client without ask_intent');
      LQ := LRoot.Objects['questions'].Objects['c2'];
      Check((LQ.Get('type', '') = 'noul') and (Pos('client 2001:db8::1', LQ.Get('instructions', '')) > 0),
        'noul question names its client');
    finally
      LData.Free;
    end;
    J.AskIntent := True;
    LData := GetJSON(J.BuildRequest(LItems));
    try
      LQ := TJSONObject(LData).Objects['questions'].Objects['i1'];
      Check((TJSONObject(LData).Objects['questions'].Count = 4) and (LQ.Get('type', '') = 'choice') and
        (LQ.Objects['criteria'].Count = 6), 'intent questions');
    finally
      LData.Free;
    end;

    Check(ParseJevResponse('{"id":"shim-1","answers":{"c1":{"type":"noul","noul":0.9731},' +
      '"c2":{"type":"noul","noul":0},"i1":{"type":"choice","choice":"vulnerability_scanner",' +
      '"probabilities":{},"confidence":0.88}},"usage":{"input_tokens":512,"output_tokens":0}}', LItems, LError),
      'response parses: ' + LError);
    Check((Abs(TJevItem(LItems[0]).Malicious - 0.9731) < 1e-9) and
      (TJevItem(LItems[0]).Intent = 'vulnerability_scanner'), 'first client answer');
    Check(TJevItem(LItems[1]).Malicious = 0, 'second client, integer noul');
    Check(not ParseJevResponse('{"answers":{"c1":{"noul":0.5}}}', LItems, LError) and (LError <> ''),
      'a missing answer fails the batch');
    Check(not ParseJevResponse('{"answers":{"c1":{"noul":1.5},"c2":{"noul":0}}}', LItems, LError),
      'out of range');
    Check(not ParseJevResponse('<html>bad gateway</html>', LItems, LError), 'not json');
  finally
    for I := 0 to LItems.Count - 1 do
      TJevItem(LItems[I]).Free;
    LItems.Free;
    J.Free;
  end;
end;

procedure TestLocal;
var
  LInfo: TLocalModelInfo;
begin
  { Python's json.dumps(s, ensure_ascii=False) }
  Check(PyJsonStr('a"b\c') = '"a\"b\\c"', 'json quotes and backslash: ' + PyJsonStr('a"b\c'));
  Check(PyJsonStr('x'#10#9#1'y') = '"x\n\t\u0001y"', 'json controls: ' + PyJsonStr('x'#10#9#1'y'));
  Check(PyJsonStr('caf'#$C3#$A9) = '"caf'#$C3#$A9'"', 'json keeps utf-8');
  Check(FindLocalModel('flash-9b', LInfo) and (LInfo.FileName = 'OpenJev-Flash-9B-Q4_K_M.gguf') and
    SameValue(LInfo.T, 1.07), 'flash-9b entry');
  Check(FindLocalModel('27B-Q8', LInfo) and (LInfo.Size = 28595763520) and SameValue(LInfo.NoulT, 1.829074), '27b-q8 entry');
  Check(not FindLocalModel('/tmp/x.gguf', LInfo), 'a path is not a key');
end;

procedure TestProviders;
var
  C: TBanConfig;
begin
  C := TBanConfig.Create;
  try
    C.Provider := 'typesafe';
    C.ApplyProvider(False, False);
    Check((C.JevUrl = 'https://api.typesafe.ai/v1/systemone') and (C.JevModel = 'jev-latest'), 'typesafe preset');
    C.Provider := 'perplexity';
    C.JevUrl := 'https://proxy.example/v1/decisions';
    C.ApplyProvider(True, False);
    Check((C.JevUrl = 'https://proxy.example/v1/decisions') and (C.JevModel = 'pplx-decider-latest'),
      'an explicit url wins over the preset');
    C.Provider := 'abacus';
    C.BatchClients := 8;
    C.MaxPerMinute := 120;
    C.ApplyProvider(False, False);
    Check((C.BatchClients = 8) and (C.MaxPerMinute = 20), 'abacus: 20 requests a minute, 8 <= 10 questions');
    C.BatchClients := 30;
    C.ApplyProvider(False, False);
    Check(C.BatchClients = 10, 'abacus: at most 10 questions a request');
    C.Provider := 'openrouter';
    try
      C.ApplyProvider(False, False);
      Check(False, 'unknown provider raises');
    except
      on E: EArgumentException do
        Check(Pos('typesafe', E.Message) > 0, 'unknown provider lists the known ones');
    end;
  finally
    C.Free;
  end;
end;

begin
  TestNet;
  TestProviders;
  TestLocal;
  TestApache;
  TestSignatures;
  TestSignatureFile;
  TestJev;
  WriteLn(Format('%d checks, %d failed', [Checks, Failures]));
  if Failures > 0 then
    ExitCode := 1;
end.
