library Erm_Hooker;

uses
  Core,
  DataLib,
  Files,
  FilesEx,
  Lists,
  SysUtils,
  Utils,

  Era;

{$R *.RES}

var
(* Map of hook address => THookData *)
{O} Hooks: {O} TObjDict {OF THookData};

const
  MAX_HOOK_SIZE        = 16;
  DEBUG_DIR            = 'Debug\Era';
  DEBUG_ERM_HOOKS_PATH = 'Debug\Era\erm hooks.txt';

  ALL_HANDLERS = 0;

type
  THookData = class;

  PBridgeCode = ^TBridgeCode;
  TBridgeCode = packed record
    PopEax:         byte;
    PushConst32:    byte;
    HookDataPtr:    pointer;
    PushEax:        byte;
    PushConst32_2:  byte;
    HookHandler:    pointer;
    Retn:           byte;
    Padding:        array [1..3] of byte;

    procedure Init ({U} HookData: THookData; aHookHandler: pointer);
  end; // .record TBridgeCode

  THookData = class
    {O} Handlers:     Lists.TList {OF ErmFunc: INTEGER};
    {O} BridgeCode:   PBridgeCode;
        OrigCode:     array [1..MAX_HOOK_SIZE] of byte;
        OrigCodeSize: integer;

    constructor Create;
    destructor  Destroy; override;
  end;

constructor THookData.Create;
begin
  Self.Handlers := Lists.NewSimpleList();
end;

destructor THookData.Destroy;
begin
  Handlers.Free();
  FreeMem(BridgeCode); BridgeCode := nil;
end;

procedure TBridgeCode.Init ({U} HookData: THookData; aHookHandler: pointer);
begin
  {!} Assert(aHookHandler <> nil);
  PopEax        := $58;
  PushConst32   := $68;
  HookDataPtr   := pointer(HookData);
  PushEax       := $50;
  PushConst32_2 := $68;
  HookHandler   := aHookHandler;
  Retn          := $C3;
end;

function OnErmCustomHook ({U} HookData: THookData; Context: PHookContext): longbool; stdcall;
var
  i: integer;

begin
  result := true;
  i      := 0;

  while i < HookData.Handlers.Count do begin
    Era.GetArgXVars()[1] := integer(Context);
    Era.GetArgXVars()[2] := 1;
    FireErmEvent(integer(HookData.Handlers[i]));
    result               := longbool(Era.GetRetXVars()[2]);

    if not result then begin
      break;
    end;

    inc(i);
  end;
end; // .function OnErmCustomHook

function SetHook (Addr: pointer; ErmHandlerFunc: integer): longbool; stdcall;
var
{U} HookData:    THookData;
    NumHandlers: integer;
    i:           integer;

begin
  {!} Assert(Addr <> nil);
  HookData := Hooks[Addr];
  // * * * * * //
  if HookData = nil then begin
    HookData              := THookData.Create;
    HookData.BridgeCode   := New(PBridgeCode);
    HookData.BridgeCode.Init(HookData, @OnErmCustomHook);
    Hooks[Addr]           := HookData;
    HookData.OrigCodeSize := CalcHookSize(Addr);
    Utils.CopyMem(HookData.OrigCodeSize, Addr, @HookData.OrigCode);
    ApiHook(HookData.BridgeCode, HOOKTYPE_BRIDGE, Addr);
  end; // .if

  i           := 0;
  NumHandlers := HookData.Handlers.Count;

  while (i < NumHandlers) and (integer(HookData.Handlers[i]) <> ErmHandlerFunc) do begin
    inc(i);
  end;

  result := i >= NumHandlers;

  if result then begin
    HookData.Handlers.Add(pointer(ErmHandlerFunc));
  end;
end; // .function SetHook

function UnsetHook (Addr: pointer; ErmHandlerFunc: integer): longbool; stdcall;
var
{U} HookData:    THookData;
    NumHandlers: integer;
    i:           integer;

begin
  {!} Assert(Addr <> nil);
  HookData := THookData(Hooks[Addr]);
  // * * * * * //
  result := HookData <> nil;

  if result then begin
    if ErmHandlerFunc = ALL_HANDLERS then begin
      HookData.Handlers.Clear();
    end else begin
      i           := 0;
      NumHandlers := HookData.Handlers.Count;

      while (i < NumHandlers) and (integer(HookData.Handlers[i]) <> ErmHandlerFunc) do begin
        inc(i);
      end;

      result := i < NumHandlers;

      if result then begin
        HookData.Handlers.Delete(i);
      end;
    end; // .else

    if HookData.Handlers.Count = 0 then begin
      WriteAtCode(HookData.OrigCodeSize, @HookData.OrigCode, Addr);
      Hooks.DeleteItem(Addr);
    end;
  end; // .if
end; // .function UnsetHook

procedure PrintHooks; stdcall;
var
{O} HooksAddrs: DataLib.TList;
{U} HookData:   THookData;
    LineStr:    string;
    Addr:       pointer;
    i, j:       integer;

begin
  HooksAddrs := GetObjDictKeys(Hooks);
  HookData   := nil;
  // * * * * * //
  Files.ForcePath(DEBUG_DIR); // For manual call not in debug event
  HooksAddrs.Sort;

  with FilesEx.WriteFormattedOutput(DEBUG_ERM_HOOKS_PATH) do begin
    Line('> Format: [Address] (Hook size) => [ERM Function], [ERM Function...]');
    EmptyLine;

    for i := 0 to HooksAddrs.Count - 1 do begin
      Addr     := HooksAddrs[i];
      HookData := THookData(Hooks[Addr]);
      LineStr  := Format('%s (%d) => ', [IntToHex(integer(Addr), 8), HookData.OrigCodeSize]);

      for j := 0 to HookData.Handlers.Count - 1 do begin
        if j > 0 then begin
          LineStr := LineStr + ', ';
        end;

        LineStr := LineStr + SysUtils.IntToStr(integer(HookData.Handlers[j]));
      end; // .for

      Line(LineStr);
    end; // .for
  end; // .with
  // * * * * * //
  FreeAndNil(HooksAddrs);
end; // .procedure PrintHooks

procedure OnResetHooks (Event: PEvent); stdcall;
var
{U} HookData: THookData;

begin
  HookData := nil;
  // * * * * * //
  with IterateObjDict(Hooks) do begin
    while IterNext do begin
      HookData := THookData(IterValue);
      WriteAtCode(HookData.OrigCodeSize, @HookData.OrigCode, IterKey);
    end;
  end;

  Hooks.Clear;
end; // .procedure OnResetHooks

procedure OnGenerateDebugInfo (Event: PEvent); stdcall;
begin
  PrintHooks;
end;

exports
  SetHook    name 'SetHook',
  UnsetHook  name 'UnsetHook',
  PrintHooks name 'PrintHooks';

begin
  Hooks := NewObjDict(OWNS_ITEMS);
  RegisterHandler(OnResetHooks,        'OnBeforeErmInstructions'); // Era 2.46
  RegisterHandler(OnResetHooks,        'OnSavegameRead');          // Era 2.46
  RegisterHandler(OnResetHooks,        'OnGameLeave');             // Era 2.47+
  RegisterHandler(OnGenerateDebugInfo, 'OnGenerateDebugInfo');     // Era 2.47+
end.
