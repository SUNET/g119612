package etsi119612

import (
	"context"
	"crypto/x509"
	"fmt"

	go_cache "github.com/eko/gocache/lib/v4/cache"
)

// todo: add validation
// todo: make a big test for the walker --- need a lotl signed mock that contains pointers to lets say existing se-tl

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

type fetchFunctionType func(string) ([]byte, error)

var FetchTSLSwapBytesFunction fetchFunctionType = FetchTSLBytes

func fetchCacheorRemote(currentURL string, cache go_cache.CacheInterface[[]byte]) (*TSL, []byte, error) {
	var bodyBytes []byte
	ctx := context.Background()
	bodyBytes, err := cache.Get(ctx, currentURL)
	fmt.Printf("cache.get %s -> err=%v len=%d\n", currentURL, err, len(bodyBytes))
	if err != nil || len(bodyBytes) == 0 {
		bodyBytes, fetchErr := FetchTSLSwapBytesFunction(currentURL)
		if fetchErr != nil {
			return nil, nil, fmt.Errorf("fetch bytes error %s, %w", currentURL, fetchErr)
		}
		setErr := cache.Set(ctx, currentURL, bodyBytes)
		if setErr != nil {
			return nil, nil, fmt.Errorf("set to cache bytes error %s, %w", currentURL, setErr)
		}
		if len(bodyBytes) == 0 {
			return nil, nil, fmt.Errorf("empty body from %s", currentURL)
		}
		//probably fix later
		tsl, unmarshError := UnmarshalCleanCerts(bodyBytes, currentURL)
		if unmarshError != nil {
			return nil, nil, fmt.Errorf("unmarshal input url=%s bytesLength=%v, error=%w", currentURL, len(bodyBytes), err)
		}
		return tsl, bodyBytes, nil
	}

	tsl, err := UnmarshalCleanCerts(bodyBytes, currentURL)
	if err != nil {
		return nil, nil, fmt.Errorf("unmarshal bytes from cache input url=%s bytesLength=%v, error=%v", currentURL, len(bodyBytes), err)
	}
	return tsl, bodyBytes, nil
}

// better to have multiple options of cache
func GraphSearch(rootURL string, cache go_cache.CacheInterface[[]byte], leafCert *x509.Certificate, intermediatePool *x509.CertPool) (*GraphUrls, error) {
	graph := NewGraph()
	visited := map[string]bool{}

	queue := []Edge{{URL: rootURL, Depth: 0}}

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		if visited[current.URL] {
			continue
		}
		visited[current.URL] = true

		tsl, bodyBytes, fetchErr := fetchCacheorRemote(current.URL, cache)
		if fetchErr != nil {
			// no error return
			fmt.Errorf("error on cache fetch %w, %d", fetchErr, len(bodyBytes))
			continue
		}
		switch {
		case tsl.IsLOTL():
			fmt.Println("is lotl")
			links, FetchError := FetchPontersToOtherListTSL(tsl)
			if FetchError != nil {
				return nil, fmt.Errorf("error on fetch pointers to other tsl %v", FetchError)

			}
			for _, link := range links {
				child := Edge{URL: link, Depth: current.Depth + 1}
				graph.AddEdge(current.URL, child)
				if !visited[link] {
					queue = append(queue, child)
				}
			}
		case tsl.IsNationalTSL():
			policy := *PolicyAll
			pool := tsl.ToCertPool(&policy)
			_, verifyErr := leafCert.Verify(x509.VerifyOptions{
				Roots: pool, Intermediates: intermediatePool})
			if verifyErr != nil {
				links, err := FetchPontersToOtherListTSL(tsl)
				if err != nil {
					panic(err)
				}
				for _, link := range links {
					child := Edge{URL: link, Depth: current.Depth + 1}
					graph.AddEdge(current.URL, child)
					if !visited[link] {
						queue = append(queue, child)
					}
				}
			} else {
				return graph, nil
			}
		default:
			fmt.Printf("unknown TSLType %s\n",
				current.URL)

		}
	}

	return graph, fmt.Errorf("no national TSL verified the leaf")
}
