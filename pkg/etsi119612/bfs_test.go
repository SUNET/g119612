package etsi119612

import (
	"testing"

	"github.com/h2non/gock"
)

func TestGraph(t *testing.T) {

	defer gock.Off()
	gock.New("https://ewc-consortium.github.io").
		Get("/EWC-TL").
		Reply(200).
		File("./testdata/EWC-TL.xml")

	graph, error := GraphSearch("https://ewc-consortium.github.io/ewc-trust-list/EWC-TL")

	if error != nil {
		t.Fatal(error)
	}
	t.Logf("%v", graph.adj["https://ewc-consortium.github.io/ewc-trust-list/EWC-TL"])

}
