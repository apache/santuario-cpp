Name:           xml-security-c
Version:        2.0.4
Release:        1
Summary:        Apache XML security C++ library
Group:          Development/Libraries/C and C++
License:        Apache 2.0
URL:            http://www.apache.org/dist/santuario/c-library/
Source:         %{name}-%{version}.tar.bz2
BuildRoot:      %{_tmppath}/%{name}-%{version}-build

%{?_with_xalan:BuildRequires: libxalan-c-devel >= 1.11}
BuildRequires:  libxerces-c-devel >= 3.2
BuildRequires:  openssl-devel gcc-c++ pkgconfig
%if "%{_vendor}" == "redhat"
BuildRequires: redhat-rpm-config
%endif

%if 0%{?rhel} >= 8 || 0%{?centos_version} >= 800
BuildRequires: gdb
%endif

%description
The xml-security-c library is a C++ implementation of the XML Digital Signature
and Encryption specifications. The library makes use of the Apache XML project's
Xerces-C XML Parser and Xalan-C XSLT processor. The latter is used for processing
XPath and XSLT transforms.

%package -n xml-security-c-bin
Summary:    Utilities for XML security C++ library
Group:      Development/Libraries/C and C++

%description -n xml-security-c-bin
The xml-security-c library is a C++ implementation of the XML Digital Signature
and Encryption specifications. The library makes use of the Apache XML project's
Xerces-C XML Parser and Xalan-C XSLT processor. The latter is used for processing
XPath and XSLT transforms.

This package contains the utility programs.

%package -n libxml-security-c20
Summary:    Apache XML security C++ library
Group:      Development/Libraries/C and C++
Provides:   xml-security-c = %{version}-%{release}

%description -n libxml-security-c20
The xml-security-c library is a C++ implementation of the XML Digital Signature
and Encryption specifications. The library makes use of the Apache XML project's
Xerces-C XML Parser and Xalan-C XSLT processor. The latter is used for processing
XPath and XSLT transforms.

This package contains just the shared library.

%package -n libxml-security-c-devel
Summary:	Development files for the Apache C++ XML security library
Group:		Development/Libraries/C and C++
Requires:	libxml-security-c20 = %{version}-%{release}
Requires:	openssl-devel
Requires:       libxerces-c-devel >= 3.2
%{?_with_xalan:Requires: libxalan-c-devel >= 1.11}
Provides:   xml-security-c-devel = %{version}-%{release}

%description -n libxml-security-c-devel
The xml-security-c library is a C++ implementation of the XML Digital Signature
and Encryption specifications. The library makes use of the Apache XML project's
Xerces-C XML Parser and Xalan-C XSLT processor. The latter is used for processing
XPath and XSLT transforms.

This package includes files needed for development with xml-security-c.

%prep
%setup -q

%build
%configure --with-openssl %{!?_with_xalan: --without-xalan} %{!?_enable_xkms: --disable-xkms}
%{__make}

%install
%{__make} install DESTDIR=$RPM_BUILD_ROOT

%clean
%{__rm} -rf $RPM_BUILD_ROOT


%post -n libxml-security-c20 -p /sbin/ldconfig

%postun -n libxml-security-c20 -p /sbin/ldconfig

%files -n xml-security-c-bin
%defattr(-,root,root,-)
%{_bindir}/*

%files -n libxml-security-c20
%defattr(-,root,root,-)
%{_libdir}/*.so.*

%files -n libxml-security-c-devel
%defattr(-,root,root,-)
%{_includedir}/*
%{_libdir}/*.so
%{_libdir}/pkgconfig/xml-security-c.pc
%exclude %{_libdir}/*.la

%changelog
* Thu Oct 14 2021 Scott Cantor <cantor.2@osu.edu> 2.0.3-1
- Bump version for OpenSSL 3 fix

* Fri Sep 27 2019 Scott Cantor <cantor.2@osu.edu> 2.0.0-2
- Add CentOS 8 dependency rule
- Remove Solaris exclusions

* Mon Nov 13 2017 Scott Cantor <cantor.2@osu.edu> 2.0.0-1
- update to 2.0.0
- exclude libtool archive

* Wed Jan 28 2015 Scott Cantor <cantor.2@osu.edu> 1.7.3-1
- update to 1.7.3
- remove support for dead Xerces versions
- switch to bzipped source to avoid SuSE problems later

* Tue May 13 2014 Ian Young <ian@iay.org.uk> 1.7.2-2.2
- fix package dependencies for RHEL/CentOS 7
- fix bogus dates in changelog

* Mon Jul 30 2012 Scott Cantor <cantor.2@osu.edu> 1.7.0-1
- update to 1.7.0
- update URL and license

* Tue Oct 26 2010 Scott Cantor <cantor.2@osu.edu> 1.6.0-1
- update to 1.6.0
- fix package dependencies for OpenSUSE 11.3+ and Xalan

* Mon Dec 28 2009 Scott Cantor <cantor.2@osu.edu> 1.5.1-2
- Sync package names for side by side installation

* Wed Aug 5 2009   Scott Cantor  <cantor.2@osu.edu> 1.5.1-1
- update to 1.5.1 and add SuSE conventions

* Sat Dec 6 2008   Scott Cantor  <cantor.2@osu.edu> 1.5-1
- update to 1.5
- fix Xerces dependency name on SUSE

* Wed Aug 15 2007   Scott Cantor  <cantor.2@osu.edu> 1.4.0-1
- update to 1.4.0

* Mon Jun 11 2007   Scott Cantor  <cantor.2@osu.edu> 1.3.1-1
- update to 1.3.1

* Thu Mar 23 2006   Ian Young     <ian@iay.org.uk> - 1.2.0-2
- patch to remove extra qualifications for compat with g++ 4.1

* Sun Jul 03 2005   Scott Cantor  <cantor.2@osu.edu> - 1.2.0-1
- Updated version.

* Tue Oct 19 2004   Derek Atkins  <derek@ihtfp.com> - 1.1.1-1
- First Package.
