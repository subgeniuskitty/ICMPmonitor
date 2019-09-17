Name: icmpmonitor
Summary: multiple host monitoring tool
Packager: Vadim Zaliva <lord@crocodile.org>
Url: http://www.crocodile.org/software.html
Version: 1.2
Release: 1
Copyright: BSD
Group: Networking/Daemons
Source: ftp://ftp.crocodile.org/pub/icmpmonitor-%{version}.tar.gz

%description
Using the InterNet Control Message Protocol (ICMP) "ECHO" facility, 
monitors several hosts, and notify admin if some of them are down.

%prep
%setup -n icmpmonitor-%{version}

%build
./configure --prefix=/usr
make

%install
make install

%files
%defattr(-,root,root)
/usr/sbin/icmpmonitor
/usr/man/man1/icmpmonitor.1
%doc README ChangeLog TODO sample.cfg NEWS


