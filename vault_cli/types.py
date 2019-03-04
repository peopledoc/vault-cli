import typing as t

JSONValue = t.Union[str, int, float, bool, None, t.Dict[str, t.Any], t.List[t.Any]]
JSONDict = t.Dict[str, JSONValue]

Settings = t.Union[str, bool, None]
SettingsDict = t.Dict[str, Settings]

VerifyOrCABundle = t.Union[bool, str]
