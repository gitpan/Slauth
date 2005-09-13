#!perl
use ExtUtils::MakeMaker;

WriteMakefile(
	'NAME'          => 'Slauth',
	'VERSION_FROM'  => 'lib/Slauth.pm',
	'ABSTRACT_FROM' => 'lib/Slauth.pm',
	'AUTHOR'	=> 'ikluft@thunder.sbay.org (Ian Kluft)',
	'PREREQ_PM'	=> {
				Digest::MD5 => 0,
				CGI => 3.00,
                                CGI::Carp => 1.28,
				CGI::Cookie => 1.24,
			},
	'EXE_FILES'	=> [ 'script/slauth-adduser' ],
);
