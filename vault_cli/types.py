import typing as t
import typing_extensions as te
import requests as r

JSONValue = t.Union[str, int, float, bool, None, t.Dict[str, t.Any], t.List[t.Any]]
JSONDict = t.Dict[str, JSONValue]

Settings = t.Union[str, bool, int, None]
SettingsDict = t.Dict[str, Settings]

VerifyOrCABundle = t.Union[bool, str]

VaultMethod = t.Literal["write","read","list","delete"]
HVACMethods = te.TypedDict("HVACMethods", {
    "list": t.Any,
    "delete":  t.Any,
    "read": t.Any,
    "write":  t.Any,
})

