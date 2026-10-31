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

   Log lines are written by the attacker, so they go in as quoted data in the
   state, never into a question; the readout is a single option letter, so
   the worst a crafted line can do is argue for a lower probability. *)

{$mode objfpc}{$H+}

interface

uses
  SysUtils, Classes, fpjson, jsonparser, DateUtils;

type
  { one client in a batch: the inputs, then the answer }
  TJevItem = class
  public
    Ip: string;
    Hits: string;
    Flagged: TStringList;     { the requests that tripped a signature }
    Earlier: TStringList;     { the client's other recent requests, oldest first }
    Malicious: Double;        { calibrated P(yes); -1 = no answer }
    Intent: string;
    constructor Create;
    destructor Destroy; override;
  end;

  TJevClient = class
  public
    Url: string;
    ApiKey: string;
    Model: string;
    Site: string;            { what this server runs, in plain words }
    Question: string;
    AskIntent: Boolean;      { a second question per client: twice the readouts }
    TimeoutMs: Integer;
    constructor Create;
    function BuildRequest(AItems: TList): string;
    { fills each item's Malicious/Intent; False with AError on any failure }
    function Decide(AItems: TList; out AError: string; out ALatencyMs: Int64): Boolean;
  end;

function ParseJevResponse(const ABody: string; AItems: TList; out AError: string): Boolean;

const
  CDefaultQuestion = 'Is this client probing for or exploiting security vulnerabilities on this ' +
    'server (vulnerability scanning, exploit attempts, hunting for secrets, admin panels or ' +
    'backups, brute-forcing logins), rather than browsing normally or crawling as a legitimate ' +
    'search engine?';
  CDefaultSite = 'A public web server. Judge requests against what a normal visitor or a ' +
    'well-behaved search engine would ask for.';

implementation

uses
  Ban.Https;

const
  CIntents: array[0..5, 0..1] of string = (
    ('legitimate_visitor', 'a person or app using the site normally, including the odd broken link'),
    ('search_crawler', 'a well-behaved search engine or monitoring bot fetching public pages'),
    ('vulnerability_scanner', 'probing many paths for known vulnerable software, admin panels, ' +
      'leaked secrets, backups or config files'),
    ('exploit_attempt', 'sending an attack payload: injection, path traversal, remote code ' +
      'execution, web shell access'),
    ('credential_attack', 'brute-forcing or stuffing passwords against a login'),
    ('abusive_scraper', 'aggressively harvesting content or bandwidth'));

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
end;

function StringsToJson(AList: TStrings): TJSONArray;
var
  I: Integer;
begin
  Result := TJSONArray.Create;
  for I := 0 to AList.Count - 1 do
    Result.Add(AList[I]);
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
      LClient.Add('signature_hits', LItem.Hits);
      LClient.Add('flagged_requests', StringsToJson(LItem.Flagged));
      LClient.Add('other_recent_requests', StringsToJson(LItem.Earlier));
      LClients.Add(LItem.Ip, LClient);

      LQ := TJSONObject.Create;
      LQ.Add('type', 'noul');
      LQ.Add('instructions', Format('%s Judge only client %s (state.clients["%s"]); the other ' +
        'clients are separate cases.', [Question, LItem.Ip, LItem.Ip]));
      LCrit := TJSONObject.Create;
      LCrit.Add('true', 'The client is attacking or probing the server and should be blocked.');
      LCrit.Add('false', 'The client is a legitimate visitor or crawler, even if a request failed.');
      LQ.Add('criteria', LCrit);
      LQuestions.Add('c' + IntToStr(I + 1), LQ);

      if AskIntent then
      begin
        LQ := TJSONObject.Create;
        LQ.Add('type', 'choice');
        LQ.Add('instructions', Format('What is client %s (state.clients["%s"]) doing?', [LItem.Ip, LItem.Ip]));
        LCrit := TJSONObject.Create;
        for J := 0 to High(CIntents) do
          LCrit.Add(CIntents[J, 0], CIntents[J, 1]);
        LQ.Add('criteria', LCrit);
        LQuestions.Add('i' + IntToStr(I + 1), LQ);
      end;
    end;
    LState.Add('clients', LClients);
    LRoot.Add('state', LState);
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

function TJevClient.Decide(AItems: TList; out AError: string; out ALatencyMs: Int64): Boolean;
var
  LBody, LResp: string;
  LStatus: Integer;
  LStart: TDateTime;
begin
  Result := False;
  LBody := BuildRequest(AItems);
  LStart := Now;
  try
    if ApiKey <> '' then
      LResp := HttpPostJson(Url, LBody, ['Authorization', 'Bearer ' + ApiKey, 'User-Agent', 'jevban/1.0'],
        TimeoutMs, LStatus)
    else
      LResp := HttpPostJson(Url, LBody, ['User-Agent', 'jevban/1.0'], TimeoutMs, LStatus);
  except
    on E: Exception do
    begin
      AError := Format('%s: %s', [E.ClassName, E.Message]);
      ALatencyMs := MilliSecondsBetween(Now, LStart);
      Exit;
    end;
  end;
  ALatencyMs := MilliSecondsBetween(Now, LStart);
  if LStatus <> 200 then
    AError := Format('HTTP %d: %s', [LStatus, Copy(LResp, 1, 160)])
  else
    Result := ParseJevResponse(LResp, AItems, AError);
end;

end.
