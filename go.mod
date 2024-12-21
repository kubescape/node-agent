module github.com/kubescape/node-agent

go 1.23.0

require (
	github.com/DmitriyVTitov/size v1.5.0
	github.com/anchore/syft v1.13.0
	github.com/aquilax/truncate v1.0.0
	github.com/armosec/armoapi-go v0.0.498
	github.com/armosec/utils-k8s-go v0.0.30
	github.com/aws/aws-sdk-go v1.55.5
	github.com/cenkalti/backoff/v4 v4.3.0
	github.com/cilium/ebpf v0.16.0
	github.com/crewjam/rfc5424 v0.1.0
	github.com/cyphar/filepath-securejoin v0.3.5
	github.com/deckarep/golang-set/v2 v2.7.0
	github.com/distribution/distribution v2.8.2+incompatible
	github.com/dustin/go-humanize v1.0.1
	github.com/dutchcoders/go-clamd v0.0.0-20170520113014-b970184f4d9e
	github.com/evanphx/json-patch v5.9.0+incompatible
	github.com/facette/natsort v0.0.0-20181210072756-2cd4dd1e2dcb
	github.com/gammazero/workerpool v1.1.3
	github.com/go-openapi/strfmt v0.23.0
	github.com/google/go-containerregistry v0.20.2
	github.com/google/uuid v1.6.0
	github.com/goradd/maps v1.0.0
	github.com/grafana/pyroscope-go v1.2.0
	github.com/hashicorp/golang-lru/v2 v2.0.7
	github.com/inspektor-gadget/inspektor-gadget v0.35.1-0.20241213182749-a4a15ff76a47
	github.com/kubescape/backend v0.0.25
	github.com/kubescape/go-logger v0.0.23
	github.com/kubescape/k8s-interface v0.0.177
	github.com/kubescape/storage v0.0.141
	github.com/moby/sys/mountinfo v0.7.2
	github.com/opencontainers/go-digest v1.0.0
	github.com/opencontainers/image-spec v1.1.0
	github.com/panjf2000/ants/v2 v2.10.0
	github.com/prometheus/alertmanager v0.27.0
	github.com/prometheus/client_golang v1.20.5
	github.com/prometheus/procfs v0.15.1
	github.com/sirupsen/logrus v1.9.3
	github.com/spf13/afero v1.11.0
	github.com/spf13/viper v1.19.0
	github.com/stretchr/testify v1.10.0
	go.opentelemetry.io/otel v1.33.0
	go.opentelemetry.io/otel/trace v1.33.0
	go.uber.org/multierr v1.11.0
	golang.org/x/net v0.33.0
	golang.org/x/sys v0.28.0
	gonum.org/v1/plot v0.14.0
	google.golang.org/grpc v1.69.0
	gopkg.in/mcuadros/go-syslog.v2 v2.3.0
	istio.io/pkg v0.0.0-20231221211216-7635388a563e
	k8s.io/api v0.31.4
	k8s.io/apimachinery v0.31.4
	k8s.io/client-go v0.31.4
	k8s.io/cri-api v0.31.4
	k8s.io/kubectl v0.31.2
	k8s.io/utils v0.0.0-20240711033017-18e509b52bc8
	sigs.k8s.io/yaml v1.4.0
)

require (
	dario.cat/mergo v1.0.1 // indirect
	git.sr.ht/~sbinet/gg v0.5.0 // indirect
	github.com/AdaLogics/go-fuzz-headers v0.0.0-20230811130428-ced1acdcaa24 // indirect
	github.com/AdamKorcz/go-118-fuzz-build v0.0.0-20231105174938-2b5cbb29f3e2 // indirect
	github.com/Azure/go-ansiterm v0.0.0-20230124172434-306776ec8161 // indirect
	github.com/BurntSushi/toml v1.4.0 // indirect
	github.com/CycloneDX/cyclonedx-go v0.9.1 // indirect
	github.com/DataDog/zstd v1.5.5 // indirect
	github.com/Masterminds/goutils v1.1.1 // indirect
	github.com/Masterminds/semver v1.5.0 // indirect
	github.com/Masterminds/semver/v3 v3.3.0 // indirect
	github.com/Masterminds/sprig/v3 v3.3.0 // indirect
	github.com/Microsoft/go-winio v0.6.2 // indirect
	github.com/Microsoft/hcsshim v0.12.9 // indirect
	github.com/ProtonMail/go-crypto v1.0.0 // indirect
	github.com/SergJa/jsonhash v0.0.0-20210531165746-fc45f346aa74 // indirect
	github.com/acobaugh/osrelease v0.1.0 // indirect
	github.com/adrg/xdg v0.5.0 // indirect
	github.com/ajstarks/svgo v0.0.0-20211024235047-1546f124cd8b // indirect
	github.com/anchore/clio v0.0.0-20240522144804-d81e109008aa // indirect
	github.com/anchore/fangs v0.0.0-20240903175602-e716ef12c23d // indirect
	github.com/anchore/go-collections v0.0.0-20240216171411-9321230ce537 // indirect
	github.com/anchore/go-logger v0.0.0-20240217160628-ee28a485904f // indirect
	github.com/anchore/go-macholibre v0.0.0-20220308212642-53e6d0aaf6fb // indirect
	github.com/anchore/go-struct-converter v0.0.0-20221118182256-c68fdcfa2092 // indirect
	github.com/anchore/go-version v1.2.2-0.20210903204242-51efa5b487c4 // indirect
	github.com/anchore/packageurl-go v0.1.1-0.20240507183024-848e011fc24f // indirect
	github.com/anchore/stereoscope v0.0.3 // indirect
	github.com/andybalholm/brotli v1.1.0 // indirect
	github.com/aquasecurity/go-pep440-version v0.0.0-20210121094942-22b2f8951d46 // indirect
	github.com/aquasecurity/go-version v0.0.0-20210121072130-637058cfe492 // indirect
	github.com/armosec/gojay v1.2.17 // indirect
	github.com/armosec/utils-go v0.0.57 // indirect
	github.com/asaskevich/govalidator v0.0.0-20230301143203-a9d515a09cc2 // indirect
	github.com/aymanbagabas/go-osc52/v2 v2.0.1 // indirect
	github.com/becheran/wildmatch-go v1.0.0 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/blang/semver/v4 v4.0.0 // indirect
	github.com/bmatcuk/doublestar/v4 v4.6.1 // indirect
	github.com/briandowns/spinner v1.23.1 // indirect
	github.com/campoy/embedmd v1.0.0 // indirect
	github.com/cenkalti/backoff v2.2.1+incompatible // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/charmbracelet/lipgloss v0.13.0 // indirect
	github.com/charmbracelet/x/ansi v0.2.3 // indirect
	github.com/cilium/cilium v1.16.4 // indirect
	github.com/cloudflare/circl v1.3.8 // indirect
	github.com/containerd/cgroups/v3 v3.0.3 // indirect
	github.com/containerd/containerd v1.7.24 // indirect
	github.com/containerd/containerd/api v1.7.19 // indirect
	github.com/containerd/continuity v0.4.3 // indirect
	github.com/containerd/errdefs v1.0.0 // indirect
	github.com/containerd/errdefs/pkg v0.3.0 // indirect
	github.com/containerd/fifo v1.1.0 // indirect
	github.com/containerd/log v0.1.0 // indirect
	github.com/containerd/platforms v0.2.1 // indirect
	github.com/containerd/stargz-snapshotter/estargz v0.15.1 // indirect
	github.com/containerd/ttrpc v1.2.6-0.20240827082320-b5cd6e4b3287 // indirect
	github.com/containerd/typeurl/v2 v2.2.0 // indirect
	github.com/containers/common v0.61.0 // indirect
	github.com/coreos/go-oidc v2.2.1+incompatible // indirect
	github.com/coreos/go-systemd/v22 v22.5.0 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/deitch/magic v0.0.0-20230404182410-1ff89d7342da // indirect
	github.com/distribution/reference v0.6.0 // indirect
	github.com/docker/cli v27.4.0+incompatible // indirect
	github.com/docker/distribution v2.8.3+incompatible // indirect
	github.com/docker/docker v27.4.0+incompatible // indirect
	github.com/docker/docker-credential-helpers v0.8.2 // indirect
	github.com/docker/go-connections v0.5.0 // indirect
	github.com/docker/go-events v0.0.0-20190806004212-e31b211e4f1c // indirect
	github.com/docker/go-units v0.5.0 // indirect
	github.com/dsnet/compress v0.0.2-0.20210315054119-f66993602bf5 // indirect
	github.com/edsrzf/mmap-go v1.1.0 // indirect
	github.com/elliotchance/phpserialize v1.4.0 // indirect
	github.com/emicklei/go-restful/v3 v3.12.1 // indirect
	github.com/emirpasic/gods v1.18.1 // indirect
	github.com/facebookincubator/nvdtools v0.1.5 // indirect
	github.com/fatih/color v1.17.0 // indirect
	github.com/felixge/fgprof v0.9.4 // indirect
	github.com/felixge/httpsnoop v1.0.4 // indirect
	github.com/francoispqt/gojay v1.2.13 // indirect
	github.com/fsnotify/fsnotify v1.8.0 // indirect
	github.com/fxamacker/cbor/v2 v2.7.0 // indirect
	github.com/gabriel-vasile/mimetype v1.4.5 // indirect
	github.com/gammazero/deque v0.2.0 // indirect
	github.com/github/go-spdx/v2 v2.3.2 // indirect
	github.com/go-errors/errors v1.5.1 // indirect
	github.com/go-fonts/liberation v0.3.2 // indirect
	github.com/go-git/gcfg v1.5.1-0.20230307220236-3a3c6141e376 // indirect
	github.com/go-git/go-billy/v5 v5.5.0 // indirect
	github.com/go-git/go-git/v5 v5.12.0 // indirect
	github.com/go-latex/latex v0.0.0-20231108140139-5c1ce85aa4ea // indirect
	github.com/go-logr/logr v1.4.2 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-openapi/analysis v0.23.0 // indirect
	github.com/go-openapi/errors v0.22.0 // indirect
	github.com/go-openapi/jsonpointer v0.21.0 // indirect
	github.com/go-openapi/jsonreference v0.21.0 // indirect
	github.com/go-openapi/loads v0.22.0 // indirect
	github.com/go-openapi/runtime v0.28.0 // indirect
	github.com/go-openapi/spec v0.21.0 // indirect
	github.com/go-openapi/swag v0.23.0 // indirect
	github.com/go-openapi/validate v0.24.0 // indirect
	github.com/go-pdf/fpdf v0.9.0 // indirect
	github.com/go-restruct/restruct v1.2.0-alpha // indirect
	github.com/godbus/dbus/v5 v5.1.0 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang/freetype v0.0.0-20170609003504-e2365dfdc4a0 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/golang/protobuf v1.5.4 // indirect
	github.com/golang/snappy v0.0.4 // indirect
	github.com/google/btree v1.1.2 // indirect
	github.com/google/gnostic-models v0.6.9-0.20230804172637-c7be7c783f49 // indirect
	github.com/google/go-cmp v0.6.0 // indirect
	github.com/google/gofuzz v1.2.0 // indirect
	github.com/google/licensecheck v0.3.1 // indirect
	github.com/google/pprof v0.0.0-20241029153458-d1b30febd7db // indirect
	github.com/google/shlex v0.0.0-20191202100458-e7afc7fbc510 // indirect
	github.com/gookit/color v1.5.4 // indirect
	github.com/gopacket/gopacket v1.3.2-0.20241202175635-b43272ae1eb8 // indirect
	github.com/gorilla/websocket v1.5.1 // indirect
	github.com/grafana/pyroscope-go/godeltaprof v0.1.8 // indirect
	github.com/gregjones/httpcache v0.0.0-20190611155906-901d90724c79 // indirect
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.24.0 // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/hashicorp/go-multierror v1.1.1 // indirect
	github.com/hashicorp/hcl v1.0.1-vault-5 // indirect
	github.com/huandu/xstrings v1.5.0 // indirect
	github.com/iancoleman/strcase v0.3.0 // indirect
	github.com/imdario/mergo v0.3.16 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/jbenet/go-context v0.0.0-20150711004518-d14ea06fba99 // indirect
	github.com/jinzhu/copier v0.4.0 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/josharian/intern v1.0.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/kastenhq/goversion v0.0.0-20230811215019-93b2f8823953 // indirect
	github.com/kevinburke/ssh_config v1.2.0 // indirect
	github.com/kinbiko/jsonassert v1.2.0 // indirect
	github.com/klauspost/compress v1.17.11 // indirect
	github.com/klauspost/pgzip v1.2.6 // indirect
	github.com/knqyf263/go-rpmdb v0.1.1 // indirect
	github.com/liggitt/tabwriter v0.0.0-20181228230101-89fcab3d43de // indirect
	github.com/lucasb-eyer/go-colorful v1.2.0 // indirect
	github.com/mackerelio/go-osstat v0.2.5 // indirect
	github.com/magiconair/properties v1.8.7 // indirect
	github.com/mailru/easyjson v0.7.7 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mattn/go-runewidth v0.0.16 // indirect
	github.com/mgutz/ansi v0.0.0-20200706080929-d51e80ef957d // indirect
	github.com/mholt/archiver/v3 v3.5.1 // indirect
	github.com/microsoft/go-rustaudit v0.0.0-20220730194248-4b17361d90a5 // indirect
	github.com/mitchellh/copystructure v1.2.0 // indirect
	github.com/mitchellh/go-homedir v1.1.0 // indirect
	github.com/mitchellh/hashstructure/v2 v2.0.2 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/mitchellh/reflectwalk v1.0.2 // indirect
	github.com/moby/docker-image-spec v1.3.1 // indirect
	github.com/moby/locker v1.0.1 // indirect
	github.com/moby/moby v27.4.0+incompatible // indirect
	github.com/moby/spdystream v0.4.0 // indirect
	github.com/moby/sys/sequential v0.5.0 // indirect
	github.com/moby/sys/signal v0.7.0 // indirect
	github.com/moby/sys/user v0.3.0 // indirect
	github.com/moby/sys/userns v0.1.0 // indirect
	github.com/moby/term v0.5.0 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/monochromegane/go-gitignore v0.0.0-20200626010858-205db1a8cc00 // indirect
	github.com/muesli/termenv v0.15.2 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/mxk/go-flowrate v0.0.0-20140419014527-cca7078d478f // indirect
	github.com/nwaples/rardecode v1.1.0 // indirect
	github.com/oklog/ulid v1.3.1 // indirect
	github.com/olekukonko/tablewriter v0.0.5 // indirect
	github.com/olvrng/ujson v1.1.0 // indirect
	github.com/opencontainers/runtime-spec v1.2.0 // indirect
	github.com/opencontainers/selinux v1.11.1 // indirect
	github.com/opentracing/opentracing-go v1.2.1-0.20220228012449-10b1cf09e00b // indirect
	github.com/pborman/indent v1.2.1 // indirect
	github.com/pelletier/go-toml v1.9.5 // indirect
	github.com/pelletier/go-toml/v2 v2.2.2 // indirect
	github.com/peterbourgon/diskv v2.0.1+incompatible // indirect
	github.com/petermattis/goid v0.0.0-20180202154549-b0b1615b78e5 // indirect
	github.com/pierrec/lz4/v4 v4.1.21 // indirect
	github.com/pjbgf/sha1cd v0.3.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pkg/profile v1.7.0 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/pquerna/cachecontrol v0.2.0 // indirect
	github.com/prometheus/client_model v0.6.1 // indirect
	github.com/prometheus/common v0.61.0 // indirect
	github.com/rivo/uniseg v0.4.7 // indirect
	github.com/s3rj1k/go-fanotify/fanotify v0.0.0-20240229202106-bca3154da60a // indirect
	github.com/saferwall/pe v1.5.4 // indirect
	github.com/sagikazarmark/locafero v0.4.0 // indirect
	github.com/sagikazarmark/slog-shim v0.1.0 // indirect
	github.com/saintfish/chardet v0.0.0-20230101081208-5e3ef4b5456d // indirect
	github.com/sasha-s/go-deadlock v0.3.1 // indirect
	github.com/sassoftware/go-rpmutils v0.4.0 // indirect
	github.com/scylladb/go-set v1.0.3-0.20200225121959-cc7b2070d91e // indirect
	github.com/secDre4mer/pkcs7 v0.0.0-20240322103146-665324a4461d // indirect
	github.com/seccomp/libseccomp-golang v0.10.0 // indirect
	github.com/sergi/go-diff v1.3.2-0.20230802210424-5b0b94c5c0d3 // indirect
	github.com/shopspring/decimal v1.4.0 // indirect
	github.com/skeema/knownhosts v1.3.0 // indirect
	github.com/sourcegraph/conc v0.3.0 // indirect
	github.com/spdx/tools-golang v0.5.5 // indirect
	github.com/spf13/cast v1.7.0 // indirect
	github.com/spf13/cobra v1.8.1 // indirect
	github.com/spf13/pflag v1.0.6-0.20210604193023-d5e0c0615ace // indirect
	github.com/stripe/stripe-go/v74 v74.30.0 // indirect
	github.com/subosito/gotenv v1.6.0 // indirect
	github.com/sylabs/sif/v2 v2.19.1 // indirect
	github.com/sylabs/squashfs v1.0.0 // indirect
	github.com/syndtr/gocapability v0.0.0-20200815063812-42c35b437635 // indirect
	github.com/therootcompany/xz v1.0.1 // indirect
	github.com/ulikunitz/xz v0.5.12 // indirect
	github.com/uptrace/opentelemetry-go-extra/otelutil v0.3.2 // indirect
	github.com/uptrace/opentelemetry-go-extra/otelzap v0.3.2 // indirect
	github.com/uptrace/uptrace-go v1.30.1 // indirect
	github.com/vbatts/go-mtree v0.5.4 // indirect
	github.com/vbatts/tar-split v0.11.6 // indirect
	github.com/vifraa/gopom v1.0.0 // indirect
	github.com/vishvananda/netlink v1.3.1-0.20241022031324-976bd8de7d81 // indirect
	github.com/vishvananda/netns v0.0.5 // indirect
	github.com/wagoodman/go-partybus v0.0.0-20230516145632-8ccac152c651 // indirect
	github.com/wagoodman/go-progress v0.0.0-20230925121702-07e42b3cdba0 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	github.com/xanzy/ssh-agent v0.3.3 // indirect
	github.com/xi2/xz v0.0.0-20171230120015-48954b6210f8 // indirect
	github.com/xlab/treeprint v1.2.0 // indirect
	github.com/xo/terminfo v0.0.0-20220910002029-abceb7e1c41e // indirect
	go.mongodb.org/mongo-driver v1.15.0 // indirect
	go.opencensus.io v0.24.0 // indirect
	go.opentelemetry.io/auto/sdk v1.1.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.53.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/runtime v0.55.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp v0.6.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp v1.30.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlptrace v1.30.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp v1.30.0 // indirect
	go.opentelemetry.io/otel/exporters/stdout/stdouttrace v1.30.0 // indirect
	go.opentelemetry.io/otel/log v0.9.0 // indirect
	go.opentelemetry.io/otel/metric v1.33.0 // indirect
	go.opentelemetry.io/otel/sdk v1.33.0 // indirect
	go.opentelemetry.io/otel/sdk/log v0.9.0 // indirect
	go.opentelemetry.io/otel/sdk/metric v1.33.0 // indirect
	go.opentelemetry.io/proto/otlp v1.4.0 // indirect
	go.starlark.net v0.0.0-20240517230649-3792562d0b7f // indirect
	go.uber.org/zap v1.27.0 // indirect
	go4.org/netipx v0.0.0-20231129151722-fdeea329fbba // indirect
	golang.org/x/crypto v0.31.0 // indirect
	golang.org/x/exp v0.0.0-20241009180824-f66d83c29e7c // indirect
	golang.org/x/image v0.18.0 // indirect
	golang.org/x/mod v0.21.0 // indirect
	golang.org/x/oauth2 v0.24.0 // indirect
	golang.org/x/sync v0.10.0 // indirect
	golang.org/x/term v0.27.0 // indirect
	golang.org/x/text v0.21.0 // indirect
	golang.org/x/time v0.6.0 // indirect
	golang.org/x/xerrors v0.0.0-20231012003039-104605ab7028 // indirect
	google.golang.org/genproto v0.0.0-20240515191416-fc5f0ca64291 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20241209162323-e6fa225c2576 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20241209162323-e6fa225c2576 // indirect
	google.golang.org/protobuf v1.36.0 // indirect
	gopkg.in/evanphx/json-patch.v4 v4.12.0 // indirect
	gopkg.in/inf.v0 v0.9.1 // indirect
	gopkg.in/ini.v1 v1.67.0 // indirect
	gopkg.in/square/go-jose.v2 v2.6.0 // indirect
	gopkg.in/warnings.v0 v0.1.2 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	k8s.io/apiextensions-apiserver v0.31.4 // indirect
	k8s.io/apiserver v0.31.4 // indirect
	k8s.io/cli-runtime v0.31.4 // indirect
	k8s.io/component-base v0.31.4 // indirect
	k8s.io/klog/v2 v2.130.1 // indirect
	k8s.io/kube-openapi v0.0.0-20240812233141-91dab695df6f // indirect
	k8s.io/kubelet v0.31.4 // indirect
	oras.land/oras-go/v2 v2.4.0 // indirect
	sigs.k8s.io/controller-runtime v0.19.3 // indirect
	sigs.k8s.io/json v0.0.0-20221116044647-bc3834ca7abd // indirect
	sigs.k8s.io/kustomize/api v0.17.2 // indirect
	sigs.k8s.io/kustomize/kyaml v0.17.1 // indirect
	sigs.k8s.io/structured-merge-diff/v4 v4.4.1 // indirect
)

replace github.com/vishvananda/netns => github.com/inspektor-gadget/netns v0.0.5-0.20230524185006-155d84c555d6

replace github.com/inspektor-gadget/inspektor-gadget => github.com/matthyx/inspektor-gadget v0.0.0-20241218095316-52e571ac842a

replace github.com/mholt/archiver/v3 v3.5.1 => github.com/anchore/archiver/v3 v3.5.2
