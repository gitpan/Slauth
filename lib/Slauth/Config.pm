# Slauth configuration

package Slauth::Config;

use strict;
#use warnings FATAL => 'all', NONFATAL => 'redefine';

#our $debug = $ENV{SLAUTH_DEBUG};
our $debug = 1;
sub debug { $debug; }

###########################################################################
# No user-servicable parts beyond this point
#
# Instead... use the Apache "SlauthConfig" directive (provided by
# Slauth::Config::Apache) or the SLAUTH_CONFIG environment variable
# to specify a Slauth configuration file.
#

# instantiate a new configuration object
sub new
{
        my $class = shift;
        my $self = {};

	debug and print STDERR "debug: Slauth::Config: new\n";

	# if an Apache request was provided, upgrade the object to
	# Slauth::Config::Apache from the start so it's mod_perl-aware
	if (( defined $_[0] ) and $_[0]->isa('Apache::RequestRec')) {
		bless $self, "Slauth::Config::Apache";
		eval "require Slauth::Config::Apache";
	} else {
		bless $self, $class;
	}
        $self->initialize(@_);
        return $self;
}

# initialize a Slauth::Config variable
# note: Slauth::Config::Apache has a separate initialize() function
# which will be used for objects blessed into its class
sub initialize
{
	my $self = shift;

	# allow SLAUTH_REALM from environment to set the request realm
	if ( defined $ENV{SLAUTH_REALM}) {
		$self->{realm} = $ENV{SLAUTH_REALM};
	}

	# allow SLAUTH_CONFIG from environment to invoke the config file
	if ( defined $ENV{SLAUTH_CONFIG}) {
		my %config;
		debug and print STDERR "debug: Slauth::Config: reading from ".$ENV{SLAUTH_CONFIG}." (from environment)\n";
		eval $self->gulp($ENV{SLAUTH_CONFIG});
		$self->{config} = \%config;

		# add "perl_inc" parameter to @INC
		if ( defined $self->{config}{global}{perl_inc}) {
			push @INC, @{$self->{config}{global}{perl_inc}};
		}
	} elsif ( -f "/etc/slauth/slauth.conf" ) {
		my %config;
		debug and print STDERR "debug: Slauth::Config: reading from /etc/slauth/slauth.conf (default)\n";
		eval $self->gulp( "/etc/slauth/slauth.conf" );
		$self->{config} = \%config;
	}

	# make a blank config if it wasn;t already created
	if ( ! defined $self->{config}) {
		debug and print STDERR "debug: Slauth::Config: empty config\n";
		$self->{config} = {};
		$self->{config}{global} = {};
		$self->{config}{$self->{realm}} = {};
	}
}

# look up a config value
sub get
{
	my ( $self, $key ) = @_;
	my ( $res );

	if ( $key eq "config" ) {
		return $self;
	}
	$res = $self->get_indirect ( undef, $self->{realm}, $key );
	if ( !defined $res ) {
		$res = $self->get_indirect ( undef, "global", $key );
	}
	return $res;
}

# look up config entry with recursive redirection if necessary
# this function is intended to be called only by get() and itself
# use get() if you want to do any kind of config lookups
sub get_indirect
{
	my ( $self, $stack, $conf_ref, $key ) = @_;

	#debug and print STDERR "get_indirect ( stack, $conf_ref, $key )\n";

	# check that $conf_ref is not already on stack
	my $i;
	if ( !defined $stack ) {
		# this relieves the initial call from responsibility to
		# allocate the stack - it uses undef instead
		$stack = [];
	}
	for ( $i=0; $i < @$stack; $i++ ) {
		if ( $conf_ref eq $stack->[$i][0]) {
			# prevent infinite loop
			return undef;
		}
	}
	push ( @$stack, [ $conf_ref, $key ]);

	# perform indirection on lookup
	my $c_type = ref $conf_ref;
	if ( ! $c_type ) {
		if ( defined $self->{config}{$conf_ref}) {
			return $self->get_indirect( $stack,
				$self->{config}{$conf_ref}, $key );
		} else {
			return undef;
		}
	} elsif ( $c_type eq "HASH" ) {
		if ( defined $conf_ref->{$key}) {
			my $i_type = ref $conf_ref->{$key};
			if ( ! $i_type ) {
				# scalar is end value
				return $conf_ref->{$key};
			} elsif ( $i_type eq "ARRAY" ) {
				my $indirect_type = $conf_ref->{$key}[0];
				my $indirect_dest = $conf_ref->{$key}[1];

				if ( $indirect_type eq "config" ) {
					return $self->get_indirect( $stack,
						$self->{config}{$indirect_dest}, $key );
				}
			} elsif ( $i_type eq "CODE" ) {
				return &{$conf_ref->{$key}}($stack->[0][0]);
			}
		} else {
			return undef;
		}
	}
}

# gulp read a configuration file into a string
sub gulp
{
	my ( $self, $file ) = @_;

	if ( open ( FILE, $file )) {
		my @text = <FILE>;
		close FILE;
		return join ('', @text );
	}
	return undef;
}
1;
