unit Ban.Jev;

(* Client for a Jev-style decision API (POST /v1/systemone): the hosted Jev
   API, or OpenJev (huggingface.co/openjev/openjev) behind its helper shim,
   which keeps the same request and response shapes. The model gets no
   training for this task; the decision is described in plain words at
   request time.

   Calls are batched: one request carries every client queued since the last
   flush, each with its own question over a shared state, so the server
   reads the state once (prefix cache) and answers N clients:

     state     = {"server": <site>, "clients": {"<ip>": {"signature_hits": ..,
                  "flagged_requests": [..], "other_recent_requests": [..]}, ..}}
     questions = "c1": noul "<question> Judge only client <ip> ..."
                 "c2": ...
                 "i1": choice over intents (only with ask_intent)

   and the answers come back as numbers, not free text:
     {"answers": {"c1": {"type": "noul", "noul": 0.97}, ..}}

   The same questions go to Google's Decisions API (gemini-decision-1, Wire =
   'gemini'), which differs only on the wire: the state is the request's
   "input" as JSON text, a noul question's criteria are true_description and
   false_description, the key goes in x-goog-api-key; the answers come back in
   the same shape.

   Log lines are written by the attacker, so they go in as quoted data in the
   state, never into a question; the readout is a single option letter, so
   the worst a crafted line can do is argue for a lower probability. *)

{$mode objfpc}{$H+}

interface

uses
  SysUtils, Classes, Math, StrUtils, fpjson, jsonparser, DateUtils;

type
  { one client in a batch: the inputs, then the answer }
  TJevItem = class
  public
    Ip: string;
    Agent: string;            { the client's usual user agent }
    Hits: string;
    Flagged: TStringList;     { the requests that tripped a signature }
    Earlier: TStringList;     { the client's other recent requests, oldest first }
    Malicious: Double;        { calibrated P(yes); -1 = no answer }
    Intent: string;
    constructor Create;
    destructor Destroy; override;
  end;

  { what the engine asks: the remote API (TJevClient) or the model in-process (Ban.Local) }
  TDecider = class
  public
    { fills each item's Malicious/Intent; False with AError on any failure }
    function Decide(AItems: TList; out AError: string; out ALatencyMs: Int64): Boolean; virtual; abstract;
    function Describe: string; virtual; abstract;
  end;

  TJevClient = class(TDecider)
  private
    FBlocked: Boolean;   { the last Post was refused by the Decisions API's safety filter }
    FLastStatus: Integer;
    FLastBody: string;
    function Post(AItems: TList; out AError: string; out ALatencyMs: Int64): Boolean;
    function PostOnce(AItems: TList; out AError: string; var ALatencyMs: Int64): Boolean;
  public
    Url: string;
    ApiKey: string;
    Model: string;
    Site: string;            { what this server runs, in plain words }
    Question: string;
    AskIntent: Boolean;      { a second question per client: twice the readouts }
    TimeoutMs: Integer;
    Wire: string;            { 'systemone' (POST /v1/systemone) or 'gemini' (Decisions API) }
    RateWaits: Integer;      { 429s waited out }
    constructor Create;
    function BuildRequest(AItems: TList): string;
    function ClientRef(const AIp: string): string;
    function Decide(AItems: TList; out AError: string; out ALatencyMs: Int64): Boolean; override;
    function Describe: string; override;
  end;

var
  { set on shutdown: a decider stops between clients and reports an error }
  DeciderAbort: Boolean = False;

function ParseJevResponse(const ABody: string; AItems: TList; out AError: string): Boolean;
{ seconds an HTTP 429 body asks to wait (1..120; 10 if it names none) }
function RetryAfterSecs(const ABody: string): Integer;

const
  CDefaultQuestion = 'Is this client probing for or exploiting security vulnerabilities on this ' +
    'server (vulnerability scanning, exploit attempts, hunting for secrets, admin panels or ' +
    'backups, brute-forcing logins), rather than browsing normally or crawling as a legitimate ' +
    'search engine?';
  CDefaultSite = 'A public web server. Judge requests against what a normal visitor or a ' +
    'well-behaved search engine would ask for.';
  CYes = 'The client is attacking or probing the server and should be blocked.';
  CNo = 'The client is a legitimate visitor or crawler, even if a request failed.';
  CIntentQuestion = 'What is this client doing?';
  CIntents: array[0..5, 0..1] of string = (
    ('legitimate_visitor', 'a person or app using the site normally, including the odd broken link'),
    ('search_crawler', 'a well-behaved search engine or monitoring bot fetching public pages'),
    ('vulnerability_scanner', 'probing many paths for known vulnerable software, admin panels, ' +
      'leaked secrets, backups or config files'),
    ('exploit_attempt', 'sending an attack payload: injection, path traversal, remote code ' +
      'execution, web shell access'),
    ('credential_attack', 'brute-forcing or stuffing passwords against a login'),
    ('abusive_scraper', 'aggressively harvesting content or bandwidth'));

implementation

uses
  Ban.Https;

{ TJevItem }

constructor TJevItem.Create;
begin
  inherited Create;
  Flagged := TStringList.Create;
  Earlier := TStringList.Create;
  Malicious := -1;
end;

destructor TJevItem.Destroy;
begin
  Earlier.Free;
  Flagged.Free;
  inherited Destroy;
end;

{ TJevClient }

constructor TJevClient.Create;
begin
  inherited Create;
  Url := 'http://127.0.0.1:3000/v1/systemone';
  Model := 'openjev';
  Site := CDefaultSite;
  Question := CDefaultQuestion;
  TimeoutMs := 8000;
  Wire := 'systemone';
end;

function StringsToJson(AList: TStrings): TJSONArray;
var
  I: Integer;
begin
  Result := TJSONArray.Create;
  for I := 0 to AList.Count - 1 do
    Result.Add(AList[I]);
end;

{ where the question points the model to its client in the shared context }
function TJevClient.ClientRef(const AIp: string): string;
begin
  if Wire = 'gemini' then
    Result := Format('clients["%s"] in the input', [AIp])
  else
    Result := Format('state.clients["%s"]', [AIp]);
end;

function TJevClient.BuildRequest(AItems: TList): string;
var
  LRoot, LState, LClients, LClient, LQuestions, LQ, LCrit: TJSONObject;
  LItem: TJevItem;
  I, J: Integer;
begin
  LRoot := TJSONObject.Create;
  try
    LRoot.Add('model', Model);
    LState := TJSONObject.Create;
    LState.Add('server', Site);
    LClients := TJSONObject.Create;
    LQuestions := TJSONObject.Create;
    for I := 0 to AItems.Count - 1 do
    begin
      LItem := TJevItem(AItems[I]);
      LClient := TJSONObject.Create;
      LClient.Add('user_agent', LItem.Agent);
      LClient.Add('signature_hits', LItem.Hits);
      LClient.Add('flagged_requests', StringsToJson(LItem.Flagged));
      LClient.Add('other_recent_requests', StringsToJson(LItem.Earlier));
      LClients.Add(LItem.Ip, LClient);

      LQ := TJSONObject.Create;
      LQ.Add('type', 'noul');
      LQ.Add('instructions', Format('%s Judge only client %s (%s); the other ' +
        'clients are separate cases.', [Question, LItem.Ip, ClientRef(LItem.Ip)]));
      LCrit := TJSONObject.Create;
      if Wire = 'gemini' then
      begin
        LCrit.Add('true_description', CYes);
        LCrit.Add('false_description', CNo);
      end
      else
      begin
        LCrit.Add('true', CYes);
        LCrit.Add('false', CNo);
      end;
      LQ.Add('criteria', LCrit);
      LQuestions.Add('c' + IntToStr(I + 1), LQ);

      if AskIntent then
      begin
        LQ := TJSONObject.Create;
        LQ.Add('type', 'choice');
        LQ.Add('instructions', Format('What is client %s (%s) doing?', [LItem.Ip, ClientRef(LItem.Ip)]));
        LCrit := TJSONObject.Create;
        for J := 0 to High(CIntents) do
          LCrit.Add(CIntents[J, 0], CIntents[J, 1]);
        LQ.Add('criteria', LCrit);
        LQuestions.Add('i' + IntToStr(I + 1), LQ);
      end;
    end;
    LState.Add('clients', LClients);
    if Wire = 'gemini' then
      { the input is text: the same state, as JSON }
      LRoot.Add('input', LState.FormatJSON([foSingleLineArray, foSingleLineObject, foSkipWhiteSpace]))
    else
      LRoot.Add('state', LState);
    if Wire = 'gemini' then
      LState.Free;
    LRoot.Add('questions', LQuestions);
    Result := LRoot.AsJSON;
  finally
    LRoot.Free;
  end;
end;

function ParseJevResponse(const ABody: string; AItems: TList; out AError: string): Boolean;
var
  LData: TJSONData;
  LAnswers, LAnswer: TJSONObject;
  LItem: TJevItem;
  I: Integer;
begin
  Result := False;
  AError := '';
  try
    LData := GetJSON(ABody);
  except
    on E: Exception do
    begin
      AError := 'response is not JSON: ' + Copy(ABody, 1, 120);
      Exit;
    end;
  end;
  try
    if not (LData is TJSONObject) or not TJSONObject(LData).Find('answers', LAnswers) then
    begin
      AError := 'response has no "answers": ' + Copy(ABody, 1, 160);
      Exit;
    end;
    for I := 0 to AItems.Count - 1 do
    begin
      LItem := TJevItem(AItems[I]);
      LItem.Malicious := -1;
      if LAnswers.Find('c' + IntToStr(I + 1), LAnswer) then
        LItem.Malicious := LAnswer.Get('noul', -1.0);
      if LAnswers.Find('i' + IntToStr(I + 1), LAnswer) then
        LItem.Intent := LAnswer.Get('choice', '');
      if (LItem.Malicious < 0) or (LItem.Malicious > 1) then
      begin
        AError := Format('answers.c%d.noul missing or out of range', [I + 1]);
        Exit;
      end;
    end;
    Result := True;
  finally
    LData.Free;
  end;
end;

function TJevClient.Describe: string;
begin
  Result := Format('%s at %s', [Model, Url]);
end;

{ the Decisions API's content blocks (HTTP 400, error.code); a malformed request is not one }
function IsSafetyBlock(AStatus: Integer; const ABody: string): Boolean;
var
  LData: TJSONData;
  LCode: string;
begin
  Result := False;
  if AStatus <> 400 then
    Exit;
  try
    LData := GetJSON(ABody);
  except
    Exit;
  end;
  try
    LCode := LData.FindPath('error.code').AsString;
    Result := (LCode = 'safety') or (LCode = 'prohibited_content') or (LCode = 'blocklist') or
      (LCode = 'image_safety') or (LCode = 'content_blocked');
  except
    Result := False;
  end;
  LData.Free;
end;

function TJevClient.Decide(AItems: TList; out AError: string; out ALatencyMs: Int64): Boolean;
var
  LOne: TList;
  I: Integer;
  LItem: TJevItem;
  LErr: string;
  LMs: Int64;
begin
  Result := Post(AItems, AError, ALatencyMs);
  if Result or not FBlocked or (AItems.Count < 2) then
    Exit;
  (* one client's text tripped the safety filter and the whole batch was refused:
     a way for an attacker to send everyone it shares a batch with to the rules.
     Ask again one client at a time; one refused even alone is put at 0.5, the
     REVIEW band (logged for an audit, not a strike) *)
  Result := True;
  AError := '';
  LOne := TList.Create;
  try
    for I := 0 to AItems.Count - 1 do
    begin
      if DeciderAbort then
      begin
        AError := 'stopping';
        Exit(False);
      end;
      LItem := TJevItem(AItems[I]);
      LOne.Clear;
      LOne.Add(LItem);
      if not Post(LOne, LErr, LMs) then
      begin
        if not FBlocked then
        begin
          AError := LErr;
          Exit(False);
        end;
        LItem.Malicious := 0.5;
        LItem.Intent := 'blocked_by_safety_filter';
      end;
      Inc(ALatencyMs, LMs);
    end;
  finally
    LOne.Free;
  end;
end;

(* seconds a 429 asks to wait: Google's "Please retry in 19s" or its retryDelay
   "19s"; 10 when the body names none. At least 1, at most 120 *)
function RetryAfterSecs(const ABody: string): Integer;
var
  P, I: Integer;
  LNum: string;
begin
  Result := 10;
  P := Pos('retry in ', LowerCase(ABody));
  if P > 0 then
    Inc(P, Length('retry in '))
  else
  begin
    P := Pos('"retryDelay"', ABody);
    if P = 0 then
      Exit;
    P := PosEx('"', ABody, P + Length('"retryDelay"'));
    if P = 0 then
      Exit;
    Inc(P);
  end;
  I := P;
  while (I <= Length(ABody)) and (ABody[I] in ['0'..'9']) do
    Inc(I);
  LNum := Copy(ABody, P, I - P);
  if LNum <> '' then
    Result := StrToIntDef(LNum, 10) + 1;   { the fraction it may give, rounded up }
  if Result < 1 then
    Result := 1;
  if Result > 120 then
    Result := 120;
end;

function TJevClient.Post(AItems: TList; out AError: string; out ALatencyMs: Int64): Boolean;
const
  CRetries = 6;
var
  LTry, LWait: Integer;
begin
  (* HTTP 429: the provider's rate limit (Gemini's free tier: 50,000 input tokens a
     minute). Wait as asked and try again: the decider has its own thread in the
     daemon, so waiting costs no reading, and decider_backlog bounds what queues
     meanwhile. Only after the retries is it an error (and the rules decide) *)
  ALatencyMs := 0;
  for LTry := 0 to CRetries do
  begin
    Result := PostOnce(AItems, AError, ALatencyMs);
    if Result or (FLastStatus <> 429) or (LTry = CRetries) then
      Exit;
    LWait := RetryAfterSecs(FLastBody) * 1000;
    while (LWait > 0) and not DeciderAbort do
    begin
      Sleep(Min(LWait, 200));
      Dec(LWait, 200);
    end;
    if DeciderAbort then
      Exit(False);
    Inc(RateWaits);
  end;
end;

function TJevClient.PostOnce(AItems: TList; out AError: string; var ALatencyMs: Int64): Boolean;
var
  LBody, LResp: string;
  LStatus: Integer;
  LStart: TDateTime;
begin
  Result := False;
  FBlocked := False;
  FLastStatus := 0;
  FLastBody := '';
  LBody := BuildRequest(AItems);
  LStart := Now;
  try
    if (ApiKey <> '') and (Wire = 'gemini') then
      LResp := HttpPostJson(Url, LBody, ['x-goog-api-key', ApiKey, 'User-Agent', 'jevban/1.0'], TimeoutMs, LStatus)
    else if ApiKey <> '' then
      LResp := HttpPostJson(Url, LBody, ['Authorization', 'Bearer ' + ApiKey, 'User-Agent', 'jevban/1.0'],
        TimeoutMs, LStatus)
    else
      LResp := HttpPostJson(Url, LBody, ['User-Agent', 'jevban/1.0'], TimeoutMs, LStatus);
  except
    on E: Exception do
    begin
      AError := Format('%s: %s', [E.ClassName, E.Message]);
      Inc(ALatencyMs, MilliSecondsBetween(Now, LStart));
      Exit;
    end;
  end;
  Inc(ALatencyMs, MilliSecondsBetween(Now, LStart));
  FLastStatus := LStatus;
  FLastBody := LResp;
  if LStatus <> 200 then
  begin
    AError := Format('HTTP %d: %s', [LStatus, Copy(LResp, 1, 160)]);
    FBlocked := (Wire = 'gemini') and IsSafetyBlock(LStatus, LResp);
  end
  else
    Result := ParseJevResponse(LResp, AItems, AError);
end;

end.
