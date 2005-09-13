# Slauth authentication

package Slauth::AAA::Authz;

use strict;
#use warnings FATAL => 'all', NONFATAL => 'redefine';

use Slauth::Config;
use Slauth::Config::Apache;
use Slauth::Storage::User_DB;
use Apache::Access ();
use Apache::RequestUtil ();
use Apache::Const -compile => qw(OK DECLINED HTTP_UNAUTHORIZED);
use Apache::Access();
use CGI::Carp qw(fatalsToBrowser);

sub debug { $Slauth::Config::debug; }

sub handler {
	my $r = shift;
	my $requires = $r->requires;
	my $auth_type = $r->auth_type;
	my ( $req );

        # check if Slauth is on in this directory
	Slauth::Config::Apache::isEnabled($r) or return Apache::DECLINED;

	# verify that we're configured to operate here
	#( $auth_type eq "Slauth" ) or return Apache::DECLINED;
	debug and print STDERR "entering Slauth::AAA::Authz\n";

	# instantiate a Slauth configuration object
	my $config = Slauth::Config->new( $r );

	for $req (@$requires) {
		( defined $req->{requirement}) or next;
		my ( $type, @subs ) = split ( /\s+/, $req->{requirement});
		if ( $type eq "user" ) {
			$r->user or return Apache::HTTP_UNAUTHORIZED;
			my $user;
			foreach $user ( @subs ) {
				if ( $user eq $r->user ) {
					debug and print STDERR "Slauth::AAA::Authz: user granted\n";
					return Apache::OK;
				}
			}
		} elsif ( $type eq "group" ) {
			$r->user or return Apache::HTTP_UNAUTHORIZED;
			my ( $user_login, $user_pw_hash, $user_salt,
				$user_name, $user_email, $user_groups )
				= Slauth::Storage::User_DB::get_user($r->user,
					$config );
			my @groups = split ( /,/, $user_groups );
			my ( $group, $sub_group );
			foreach $group ( @groups ) {
				foreach $sub_group ( @subs ) {
					if ( $group eq $sub_group ) {
						debug and print STDERR "Slauth::AAA::Authz: group granted\n";
						return Apache::OK;
					}
				}
			}
		} elsif ( $type eq "valid-user" ) {
			if ( defined $r->user ) {
				debug and print STDERR "Slauth::AAA::Authz: valid-user granted\n";
				return Apache::OK;
			}
		}
	}

	debug and print STDERR "Slauth::AAA::Authz: denied\n";
	$r->note_basic_auth_failure;
	return Apache::HTTP_UNAUTHORIZED;
}

1;
