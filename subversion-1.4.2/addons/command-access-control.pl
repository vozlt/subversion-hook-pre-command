#!/usr/bin/perl
#
# @file: command-access-control.pl
# @brief: pre-command hook perl script
# @author: YoungJoo.Kim <vozlt@vozlt.com>
# @version:
# @date:
#

my $repos = shift;
my $cmdname = shift;
my $target = shift;
my $user = shift;
my $conf = shift;

my $ACCESS = Access::new($repos, $cmdname, $target, $user, $conf);

$ACCESS->checkAnonymous();
$ACCESS->getConfig();
$ACCESS->checkPerms();

# Package Start
package Access;

use strict;
use Fcntl;
use IO::Handle;

use vars qw(%groups @users %perms @passwd @group);

sub new{

	my $self = {};
	$self->{repos} = shift if defined($_[0]);
	$self->{cmdname} = shift if defined($_[0]);
	$self->{target} = shift if defined($_[0]);
	$self->{user} = shift if defined($_[0]);
	$self->{conf} = shift if defined($_[0]);

	return bless $self;
}

sub checkAnonymous {
	my $self = shift if ref ($_[0]);
	my $user = $_[0] ? $_[0] : $self->{user};
	my $ret = 0;
	exit(0) if ($user eq '<anonymous>');
}

sub checkPerms {
	my $self = shift if ref ($_[0]);
	my $user = $_[0] ? $_[0] : $self->{user};
	my $cmdname = $_[1] ? $_[1] : $self->{cmdname};
	my $ret = 0;

	if ($perms{$user}) {
		if ($perms{$user}{'access'} =~ /allow/i ) {
			if ($perms{$user}{'cmds'} eq '*') {
				$ret = 0;
			} else {
				if ($perms{$user}{'cmds'} =~ /$cmdname/i) {
					$ret = 0;
				} else {
					$ret = 1;
				}
			}
		} else {
			if ($perms{$user}{'cmds'} eq '*') {
				$ret = 1;
			} else {
				if ($perms{$user}{'cmds'} =~ /$cmdname/i) {
					$ret = 1;
				} else {
					$ret = 0;
				}
			} 
		}
	} elsif ($perms{'*'}) {
		if ($perms{'*'}{'access'} =~ /allow/i ) {
			if ($perms{'*'}{'cmds'} eq '*') {
				$ret = 0;
			} else {
				if ($perms{'*'}{'cmds'} =~ /$cmdname/i) {
					$ret = 0;
				} else {
					$ret = 1;
				}
			} 

		} else {

			if ($perms{'*'}{'cmds'} eq '*') {
				$ret = 1;
			} else {
				if ($perms{'*'}{'cmds'} =~ /$cmdname/i) {
					$ret = 1;
				} else {
					$ret = 0;
				}
			}
		}
	} else {
		$ret = 1;
	}

	$ret = 0 if (!%perms);

	exit($ret);
}

sub getUsers {
	my $self = shift if ref ($_[0]);
	my @tmpa = ();  
	my @tmpb = ();  

	$self->getGrouppush();
	$self->getPasswdpush();

	foreach(@group) {
		chomp $_;
		@tmpa = split(/:/, $_);
		$groups{$tmpa[0]} = $tmpa[3] . $self->getGroupadd($tmpa[2]);
		@tmpb = split(/,/, $tmpa[3]);
		foreach(@tmpb) {
			push(@users, $_);
		}
	}
}

sub getGroupname {
	my $self = shift if ref ($_[0]);
	my $uname = $_[0];
	my @r = ();
	my $gid = undef;
	my $gname = undef;

	@r = getpwnam($uname);
	$gid = $r[3];
	@r = getgrgid($gid);
	$gname = $r[0];

	return $gname;
}

sub getGroup {
	my $self = shift if ref ($_[0]);
	my $gname = $_[0];
	my @r = ();
	my $members = undef;
	@r = getgrnam($gname);
	$members = $r[3];
	$members =~ s/ /,/g;
	# "$r[0]:$r[1]:$r[2]:$members";
	return $members;
}

sub getPasswdpush {
	my $self = shift if ref ($_[0]);
	my @r = ();
	while(@r = getpwent()) {
		# $name,$passwd,$uid,$gid,$quota,$comment,$gcos,$dir,$shell,$expire
		push(@passwd, "$r[0]:$r[1]:$r[2]:$r[3]:$r[6]:$r[7]:$r[8]");
	}
}

sub getGrouppush {
	my $self = shift if ref ($_[0]);
	my @r = ();
	my $members = undef;
	while(@r = getgrent()) {
		# $name,$passwd,$gid,$members
		$members = $r[3];
		$members =~ s/ /,/g;
		push(@group, "$r[0]:$r[1]:$r[2]:$members");
	}
}

sub getGroupadd {
	my $self = shift if ref ($_[0]);
	my $gid = $_[0];
	my @tmpa = ();
	my $grs = undef;

	foreach(@passwd) {
		chomp $_;
		@tmpa = split(/:/, $_);
		if ($gid eq $tmpa[3]) {
			$grs	.= (!$grs) ? "$tmpa[0]" : ",$tmpa[0]";
		}
	}
	return $grs;
}

sub getConfig {
	my $self = shift if ref ($_[0]);
	my $path = $self->{repos} . '/conf/' . $self->{conf};
	my @tmpa = ();
	my @tmpb = ();
	my @tmpc = ();
	my @tmpd = ();
	my $gname = $self->getGroupname($self->{user});

	@tmpa = fileReadlines($path);
	exit(0) if(!$tmpa[0]);

	foreach(@tmpa) {
		if ( $_ !~ /[\s]*[#;]/ ) {
			$_ = $self->trim($_);
			@tmpb = split(/:/, $_);
			@tmpc = split(/,/, $tmpb[0]);	
			foreach(@tmpc) {
				if ($_ =~ /^\%/) {
					$_ =~ s/%//g;

					@tmpd = split(/,/, $self->getGroup($_));

					if ($gname eq $_ && !(grep{$self->{user} eq $_} @tmpd)) {
						push(@tmpd, $self->{user});
					}

					foreach(@tmpd) {
						$perms{$_}{'cmds'} = $tmpb[1];
						$perms{$_}{'access'} = $tmpb[2];
					}
				} elsif ($tmpb[0] =~ /^\*/) {
					$perms{'*'}{'cmds'} = $tmpb[1];
					$perms{'*'}{'access'} = $tmpb[2];
				} else {
					$perms{$_}{'cmds'} = $tmpb[1];
					$perms{$_}{'access'} = $tmpb[2];
				}
			}
		}
	}

}

sub trim {
	my $self = shift if ref ($_[0]);
	my $_r = $_[0];

	$_r =~ s/[\s\n]*//g;

	return $_r;
}

sub fileReadlines { 
	my $self = shift if ref ($_[0]);
	my $path = $_[0];
	my $ret = undef;
	my @lines = ();  
	$ret = sysopen(FH, $path, O_RDONLY);
	@lines = FH->getlines() if ($ret);
	close(FH);      
	return ($ret) ? @lines : $ret;
}

