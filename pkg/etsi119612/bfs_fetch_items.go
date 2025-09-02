package etsi119612

import (
	"fmt"
	"net/http"
)

// pointer here insteda of value?
type GraphUrls struct {
	adj map[string][]Edge
}

type Edge struct {
	URL   string
	Depth int
}

func NewGraph() *GraphUrls {
	return &GraphUrls{adj: make(map[string][]Edge)}
}

func (g *GraphUrls) AddEdge(parentURL string, edge Edge) {
	g.adj[parentURL] = append(g.adj[parentURL], edge)
}

func GraphSearch(rootURL string) (*GraphUrls, error) {
	graph := NewGraph()
	visited := map[string]bool{}
	queue := []Edge{{URL: rootURL, Depth: 0}}

	//should be in loop
	//to check the graph algorythm only, otherwise multiple middle steps
	_, err := http.Get(rootURL)
	if err != nil {
		panic(err)
	}

	for len(queue) > 0 {

		current := queue[0]
		queue = queue[1:]

		if visited[current.URL] {
			continue
		}
		visited[current.URL] = true
		fmt.Println(current.URL)

		//cache bytes and other stages here?

		//here come links fetched from the xml, mock for now
		links := []string{"https://SE-TL.se", "https://NL-TL.se"}

		for _, link := range links {

			child := Edge{URL: link, Depth: current.Depth + 1}
			graph.AddEdge(current.URL, child)
			if !visited[link] {
				queue = append(queue, child)
			}

		}

		if current.Depth == 0 {
			graph.AddEdge("", Edge{URL: rootURL, Depth: 0})
		}

	}
	return graph, nil
}
