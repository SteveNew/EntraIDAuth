unit EntraIDAuth;

interface

uses
  Winapi.Windows,
  System.SysUtils, System.Classes,
  Vcl.Controls, Vcl.OleCtrls,
  SHDocVw, Mshtmhst,

  JOSE.Core.JWT,
  JOSE.Core.JWS,
  JOSE.Core.JWK,
  JOSE.Types.JSON;

const
  DOCHOSTUIFLAG_ENABLE_REDIRECT_NOTIFICATION = $04000000;

type
  TClaims = class(TJWTClaims)
  // Adding some given by the OpenID Connect scope: profile or email
  private
    function GetUniqueUsername: string;
    procedure SetUniqueUsername(const value: string);
    function GetGivenName: string;
    procedure SetGivenName(const value: string);
    function GetFamilyName: string;
    procedure SetFamilyName(const value: string);
  public
    property UniqueUsername: string read GetUniqueUsername write SetUniqueUsername;
    property GivenName: string read GetGivenName write SetGivenName;
    property FamilyName: string read GetFamilyName write SetFamilyName;
  end;

  // Claims where to get a unique id for the user from
  // - sub is unique, but not that useable as it neither is known by user or relateable
  // - preferred_username, is unique and what the user identifies as in the login process. So best and default option.
  {$SCOPEDENUMS ON}
  TUserIdClaim = (unique_name, sub);
  {$SCOPEDENUMS OFF}

  [ComponentPlatformsAttribute(pidWin32 or pidWin64)]
  TEntraIDAuth = class(TWebBrowser, IDocHostUIHandler)
  strict private
    // IDocHostUIHandler "override"
    function GetHostInfo(var pInfo: TDocHostUIInfo): HRESULT; stdcall;
  private
    { Private declarations }
    FOrganizationId: string;
    FAuthPath: string;
    FClientID: string;
    FClientSecret: string;
    FRedirectUri: string;
    FAuthEndpoint: string;
    FTokenEndpoint: string;
    FScope: string;
    FResponseType: string;
    FAuthCode: string;
    FAccessToken: string;
    FUserId: string;
    FGreetName: string;
    FUserIdClaim: TUserIdClaim;
    FOnAuthenticated: TNotifyEvent;
    FOnDenied: TNotifyEvent;
  protected
    { Protected declarations }
  public
    { Public declarations }
    constructor Create(AOwner: TComponent); override;
    procedure BeforeNavigate2(ASender: TObject; const pDisp: IDispatch; const URL, Flags, TargetFrameName, PostData, Headers: OleVariant;
      var Cancel: WordBool);
    procedure Authorize;
    property AccessToken: string read FAccessToken;
    property UserId: string read FUserId write FUserId;
    property GreetName: string read FGreetName write FGreetName;
  published
    { Published declarations }
    property OrganizationId: string read FOrganizationId write FOrganizationId;
    property AuthPath: string read FAuthPath write FAuthPath;
    property ClientId: string read FClientID write FClientID;
    property ClientSecret: string read FClientSecret write FClientSecret;
    property RedirectUri: string read FRedirectUri write FRedirectUri;
    property AuthEndpoint: string read FAuthEndpoint write FAuthEndpoint;
    property TokenEndpoint: string read FTokenEndpoint write FTokenEndpoint;
    property Scope: string read FScope write FScope;
    property ResponseType: string read FResponseType write FResponseType;
    property UserIdClaim: TUserIdClaim read FUserIdClaim write FUserIdClaim;
    property OnAuthenticated: TNotifyEvent read FOnAuthenticated write FOnAuthenticated;
    property OnDenied: TNotifyEvent read FOnDenied write FOnDenied;
  end;

procedure Register;

implementation

uses
  System.NetEncoding,
  System.Net.HTTPClient,
  System.Net.HttpClientComponent,
  System.JSON;

procedure Register;
begin
  RegisterComponents('FixedByCode', [TEntraIDAuth]);
end;

{ TEntraIDAuth }

procedure TEntraIDAuth.Authorize;
var
  URL: string;
begin
  URL := FAuthPath + FOrganizationId + FAuthEndpoint + '?response_type=' + FResponseType + '&client_id=' + FClientID + '&redirect_uri=' +
    TNetEncoding.URL.Encode(FRedirectUri) + '&scope=' + TNetEncoding.URL.Encode(FScope);
  Navigate(URL);
end;

procedure TEntraIDAuth.BeforeNavigate2(ASender: TObject; const pDisp: IDispatch;
  const URL, Flags, TargetFrameName, PostData, Headers: OleVariant;
  var Cancel: WordBool);
var
  uri: string;
  HTTP: TNetHTTPClient;
  lRequestBody: TStringStream;
  lResponse: IHTTPResponse;
  lJSONResponse: TJSONObject;

  LKey: TJWK;
  LToken: TJWT;
  LClaims: TClaims;
  LSigner: TJWS;
begin
  uri := URL;
  if uri.StartsWith(FRedirectUri + '?code=', True) then
  begin
    // Stop navigation since we are done - just need to get the id_token.
    Self.Stop;
    FAccessToken := '';
    FAuthCode := uri.Substring(Length(FRedirectUri + '?code='));
    Cancel := True;
    // Call token with code
    lRequestBody := nil;
    lJSONResponse := nil;
    HTTP := TNetHTTPClient.Create(nil);
    try
      // pre-URL encode content
      lRequestBody := TStringStream.Create('grant_type=authorization_code&code=' + FAuthCode + '&redirect_uri=' + FRedirectUri +
        '&client_id=' + FClientID);
      HTTP.ContentType := 'application/x-www-form-urlencoded';
      lResponse := HTTP.Post(FAuthPath + FOrganizationId + FTokenEndpoint, lRequestBody);
      if lResponse.StatusCode = 200 then
      begin
        lJSONResponse := TJSONObject.ParseJSONValue(lResponse.ContentAsString) as TJSONObject;
        FAccessToken := lJSONResponse.Values['access_token'].value;
      end;
    finally
      FreeAndNil(HTTP);
      FreeAndNil(lJSONResponse);
      FreeAndNil(lRequestBody);
    end;

    if FAccessToken <> '' then
    begin
      LKey := TJWK.Create(FClientSecret);
      try
        LToken := TJWT.Create(TClaims);
        try
          LSigner := TJWS.Create(LToken);
          try
            LSigner.SkipKeyValidation := True;
            LSigner.SetKey(LKey);
            LSigner.CompactToken := FAccessToken;

            LClaims := LToken.Claims as TClaims;

            case FUserIdClaim of
              TUserIdClaim.unique_name: FUserId := LClaims.UniqueUsername;
              TUserIdClaim.sub: FUserId := LClaims.Subject;
            end;

            FGreetName := Trim(LClaims.GivenName + ' ' + LClaims.FamilyName);
          finally
            LSigner.Free;
          end;
        finally
          LToken.Free;
        end;
      finally
        LKey.Free;
      end;
      // If we do not get the OpenId Connect profile scope back - we will not know who got autenticated, so...
      if (FUserId <> '') and Assigned(OnAuthenticated) then
        OnAuthenticated(Self);
    end
    else
    begin
      if Assigned(OnDenied) then
        OnDenied(Self);
    end;
    Self.Navigate('about:blank');
  end;
end;

constructor TEntraIDAuth.Create(AOwner: TComponent);
begin
  inherited;
  FResponseType := 'code';
  FScope := 'User.Read';
  FUserIdClaim := TUserIdClaim.unique_name;
  // Due to IE not being supported anymore and lack "correct" handling of strict JS code -
  // use (Edge)WebView2 runtime and deploy WebView2Loader.dll in the bitness required with your application - if possible
  SelectedEngine := TSelectedEngine.EdgeIfAvailable;
  OnBeforeNavigate2 := BeforeNavigate2;
end;

function TEntraIDAuth.GetHostInfo(var pInfo: TDocHostUIInfo): HRESULT;
begin
  pInfo.cbSize := SizeOf(pInfo);
  pInfo.dwFlags := 0;
  pInfo.dwFlags := pInfo.dwFlags or DOCHOSTUIFLAG_NO3DBORDER;
  pInfo.dwFlags := pInfo.dwFlags or DOCHOSTUIFLAG_THEME;
  pInfo.dwFlags := pInfo.dwFlags or DOCHOSTUIFLAG_ENABLE_REDIRECT_NOTIFICATION;
  Result := S_OK;
end;

{ TClaims }

function TClaims.GetFamilyName: string;
begin
  Result := TJSONUtils.GetJSONValue('family_name', FJSON).AsString;
end;

function TClaims.GetGivenName: string;
begin
  Result := TJSONUtils.GetJSONValue('given_name', FJSON).AsString;
end;

function TClaims.GetUniqueUsername: string;
begin
  Result := TJSONUtils.GetJSONValue('unique_name', FJSON).AsString;
end;

procedure TClaims.SetFamilyName(const value: string);
begin
  TJSONUtils.SetJSONValueFrom<string>('family_name', value, FJSON);
end;

procedure TClaims.SetGivenName(const value: string);
begin
  TJSONUtils.SetJSONValueFrom<string>('given_name', value, FJSON);
end;

procedure TClaims.SetUniqueUsername(const value: string);
begin
  TJSONUtils.SetJSONValueFrom<string>('unique_name', value, FJSON);
end;

end.
