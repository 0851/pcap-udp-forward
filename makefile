
mk = rm -rf upx/$(1)$(2)/$(3) \
&& mkdir -p upx/$(1)$(2) \
&& mkdir -p build/$(1)$(2) \
&& GOOS=$(1) GOARCH=$(2) go build -ldflags '-w -s' -o build/$(1)$(2)/$(3) \
&& upx -9 -o upx/$(1)$(2)/$(3) build/$(1)$(2)/$(3)

forward-mips:
	$(call mk,linux,mips,$@)
forward-linux:
	$(call mk,linux,amd64,$@)
forward-darwin:
	$(call mk,darwin,amd64,$@)
forward-windows:
	$(call mk,windows,amd64,$@)

