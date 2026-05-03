Name:           thinproxy
Version:        0.1.3
Release:        1%{?dist}
Summary:        Lightweight asynchronous HTTP/HTTPS proxy
License:        BSD-2-Clause
URL:            https://github.com/renaudallard/thinproxy
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  gcc make

%description
thinproxy is a minimal, single-threaded HTTP/HTTPS proxy with a small
memory footprint. It uses non-blocking I/O with poll(2) for asynchronous
event handling and supports both HTTP request forwarding and HTTPS
tunneling via the CONNECT method.

%prep
%setup -q

%build
make %{?_smp_mflags}

%install
make install DESTDIR=%{buildroot} PREFIX=/usr UNITDIR=/lib/systemd/system

%files
%license LICENSE
%doc README.md thinproxy.conf.example
%{_bindir}/thinproxy
%{_mandir}/man8/thinproxy.8*
/lib/systemd/system/thinproxy.service
