package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	personalWebsite = "www.andrewwillette.com"
)

func TestGetDnsARecord(t *testing.T) {
	arecord, err := getDnsARecord(personalWebsite)
	require.NoError(t, err)
	require.Equal(t, "18.191.185.163", arecord)
}

func TestGetDnsCNamesSuccess(t *testing.T) {
	cnames, err := getDnsCNames("www.youtube.com")
	require.NoError(t, err)
	require.Equal(t, "youtube-ui.l.google.com.", cnames[0])
}

func TestGetDnsCNamesEmptyCnames(t *testing.T) {
	cnames, err := getDnsCNames(personalWebsite)
	require.NoError(t, err)
	require.Empty(t, cnames)
}
