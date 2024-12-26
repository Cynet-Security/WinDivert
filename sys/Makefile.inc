!IF "$(_BUILDARCH)" == "x86"
CPU=i386
!ELSE
CPU=$(_BUILDARCH)
!ENDIF

$(TARGETPATH)\$(CPU)\CyDivert.inf: cydivert.inf
	copy /y cydivert.inf $@
$(TARGETPATH)\$(CPU)\WdfCoInstaller01009.dll:
	copy /y $(BASEDIR)\redist\wdf\$(_BUILDARCH)\WdfCoInstaller01009.dll $@
