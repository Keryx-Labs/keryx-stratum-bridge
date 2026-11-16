package gostratum

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

type JsonRpcEvent struct {
	Id      any           `json:"id"` // id can be nil, a string, or an int 🙄
	Version string        `json:"jsonrpc"`
	Method  StratumMethod `json:"method"`
	Params  []any         `json:"params"`
}

type JsonRpcResponse struct {
	Id     any   `json:"id"`
	Result any   `json:"result"`
	Error  []any `json:"error"`
}

func NewEvent(id string, method string, params []any) JsonRpcEvent {
	var finalId any
	if len(id) == 0 {
		finalId = nil
	} else {
		finalId = id
	}

	return JsonRpcEvent{
		Id:      finalId,
		Version: "2.0",
		Method:  StratumMethod(method),
		Params:  params,
	}
}

func NewResponse(event JsonRpcEvent, results any, err []any) JsonRpcResponse {
	return JsonRpcResponse{
		Id:     event.Id,
		Result: results,
		Error:  err,
	}
}

func UnmarshalEvent(in string) (JsonRpcEvent, error) {
	event := JsonRpcEvent{}
	decoder := json.NewDecoder(strings.NewReader(in))
	decoder.UseNumber()
	if err := decoder.Decode(&event); err != nil {
		return JsonRpcEvent{}, err
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return JsonRpcEvent{}, fmt.Errorf("multiple or malformed JSON values in frame")
	}
	return event, nil
}

func UnmarshalResponse(in string) (JsonRpcResponse, error) {
	resp := JsonRpcResponse{}
	if err := json.Unmarshal([]byte(in), &resp); err != nil {
		return JsonRpcResponse{}, err
	}
	return resp, nil
}
