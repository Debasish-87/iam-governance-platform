package main

type GraphNode struct {
	ID   string `json:"id"`
	Type string `json:"type"`
}

type GraphEdge struct {
	Source string `json:"source"`
	Target string `json:"target"`
	Reason string `json:"reason"`
	Risk   string `json:"risk"`
}

type AttackGraph struct {
	Nodes []GraphNode `json:"nodes"`
	Edges []GraphEdge `json:"edges"`
}

type PolicyDocument struct {
	Version   string      `json:"Version"`
	Statement []Statement `json:"Statement"`
}

type Statement struct {
	Effect   string      `json:"Effect"`
	Action   interface{} `json:"Action"`
	Resource interface{} `json:"Resource"`
}