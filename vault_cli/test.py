import typing as t
from requests import Response as HTTPResponse

JSONValue = t.Union[str, int, float, bool, None, t.Dict[str, t.Any], t.List[t.Any]]
JSONDict = t.Dict[str, JSONValue]

class V1:
    def list(self, path:str, mount:t.Optional[str]="default") -> JSONDict:
        return {"r":"toutou"}    
    def read(self, path:str, mount:t.Optional[str]="default") -> JSONDict:
        return {"r":"toutou"}            
    def delete(self, path:str, mount:t.Optional[str]="default") -> HTTPResponse:
        return HTTPResponse()                
    def create(self, path:str, secret:JSONDict, method:t.Optional[str]=None, mount:t.Optional[str]="default") -> HTTPResponse:
        return HTTPResponse()                    

class V2:
    def list(self, path:str, mount:str="default") -> JSONDict:
        return {"r":"toutou"}        
    def read(self, path:str, version:t.Optional[int]=None ,mount:t.Optional[str]="default") -> JSONDict:
        return {"r":"toutou"}            
    def delete(self, path:str, mount:str="default") -> HTTPResponse:
        return HTTPResponse()              
    def create(self, path:str, secret:JSONDict, method:t.Optional[str]=None, mount:t.Optional[str]="default") -> JSONDict:
        return {"r":"toutou"}              

def f(yolo: t.Callable[[str, t.Optional[str]], JSONDict]):
    pass
v1 = V1()
f(v1.create)