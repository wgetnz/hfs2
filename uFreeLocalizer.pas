unit uFreeLocalizer;

interface

type
  TFreeLocalizer = class
  public
    AutoTranslate: Boolean;
    LanguageFile: string;
  end;

var
  FreeLocalizer: TFreeLocalizer;

implementation

initialization
  FreeLocalizer := TFreeLocalizer.Create;

finalization
  FreeLocalizer.Free;

end.
