#!/usr/bin/perl
#
# @file: command-access-control.pl
# @brief: pre-command hook perl script
# @author: YoungJoo.Kim <http://superlinuxer.com>
# @version: $Revision:
# @date: $Date:
#

my $repos = shift;
my $cmdname = shift;
my $target = shift;
my $user = shift;
my $conf = shift;
my $remote_ip = shift;

my $ACCESS = Access::new($repos, $cmdname, $target, $user, $conf, $remote_ip);

$ACCESS->Controller();

# Package Start
package Access;

use strict;
use Fcntl;
use IO::Handle;
use DBI;

use vars qw(%groups @users %perms @passwd @group);
use vars qw($SUCCESS $FAIL @RESULTS);

sub new{

	my $self = {};
	$self->{repos} = shift if defined($_[0]);
	$self->{cmdname} = shift if defined($_[0]);
	$self->{target} = shift if defined($_[0]);
	$self->{user} = shift if defined($_[0]);
	$self->{conf} = shift if defined($_[0]);
	$self->{remote_ip} = shift if defined($_[0]);
	$self->{access_method} = undef;
	$self->{access_file} = 'access_file.conf';
	$self->{access_db} = 'access_db.conf';

	$self->{hostname} =`/bin/hostname`; chomp $self->{hostname};

	# DBI
	$self->{access_db_host} = undef;
	$self->{access_db_port} = undef;
	$self->{access_db_name} = undef;
	$self->{access_db_user} = undef;
	$self->{access_db_password} = undef;
	$self->{n_rows} = undef;
	$self->{n_fields} = undef;
	$self->{dbh} = undef;
	$self->{sth} = undef;

	$self->{result} = undef;

	$SUCCESS = 0;
	$FAIL = 1;

	$RESULTS[$SUCCESS] = 'ALLOW';
	$RESULTS[$FAIL] = 'DENY';

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
	my $ret = $SUCCESS;

	if ($perms{$user}) {
		if ($perms{$user}{'access'} =~ /allow/i ) {
			if ($perms{$user}{'cmds'} eq '*') {
				$ret = $SUCCESS;
			} else {
				if ($perms{$user}{'cmds'} =~ /$cmdname/i) {
					$ret = $SUCCESS;
				} else {
					$ret = $FAIL;
				}
			}
		} else {
			if ($perms{$user}{'cmds'} eq '*') {
				$ret = $FAIL;
			} else {
				if ($perms{$user}{'cmds'} =~ /$cmdname/i) {
					$ret = $FAIL;
				} else {
					$ret = $SUCCESS;
				}
			} 
		}
	} elsif ($perms{'*'}) {
		if ($perms{'*'}{'access'} =~ /allow/i ) {
			if ($perms{'*'}{'cmds'} eq '*') {
				$ret = $SUCCESS;
			} else {
				if ($perms{'*'}{'cmds'} =~ /$cmdname/i) {
					$ret = $SUCCESS;
				} else {
					$ret = $FAIL;
				}
			} 

		} else {

			if ($perms{'*'}{'cmds'} eq '*') {
				$ret = $FAIL;
			} else {
				if ($perms{'*'}{'cmds'} =~ /$cmdname/i) {
					$ret = $FAIL;
				} else {
					$ret = $SUCCESS;
				}
			}
		}
	} else {
		$ret = $FAIL;
	}

	$ret = $SUCCESS if (!%perms);

	if ($self->{access_method} eq 'db') {
		$self->{result} = $RESULTS[$ret];
		$self->logInsert();
	}

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

sub getConfigFile {
	my $self = shift if ref ($_[0]);
	my $path = $self->{repos} . '/conf/' . $self->{access_file};
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

sub getConfigDb {
	my $self = shift if ref ($_[0]);
	my $query = undef;
	my $ref = undef;
	my $ret = $SUCCESS;

	$self->dbConnect($self->{access_db_host}, $self->{access_db_port}, $self->{access_db_name}, $self->{access_db_user}, $self->{access_db_password});
	$query = "SELECT * FROM svn_conf WHERE hostname='$self->{hostname}' AND repos='$self->{repos}' AND user='$self->{user}';";

	$self->dbQuery($query);

	if ($ref = $self->dbFetch()) {
		$perms{$ref->{user}}{'cmds'} = $ref->{cmdname};
		$perms{$ref->{user}}{'access'} = $ref->{access};

	} else {
		$self->{result} = $RESULTS[$FAIL];
		$self->logInsert();	
		exit($FAIL);
	}

	$self->dbFetchfinish();
	$self->dbClose();
}

sub logInsert {
	my $self = shift if ref ($_[0]);
	my $query = undef;
	my $ref = undef;

	$query = "INSERT INTO svn_log(hostname, repos, cmdname, target, user, remoteaddr, access) VALUES('$self->{hostname}', '$self->{repos}', '$self->{cmdname}', '$self->{target}', '$self->{user}', '$self->{remote_ip}', '$self->{result}');";
	$self->dbConnect($self->{access_db_host}, $self->{access_db_port}, $self->{access_db_name}, $self->{access_db_user}, $self->{access_db_password});
	$self->dbQuery($query);
	$self->dbFetchfinish();
	$self->dbClose();
}

sub getAccessmethod {
	my $self = shift if ref ($_[0]);
	my $path = $self->{repos} . '/conf/' . $self->{conf};
	my @tmpa = ();
	my @tmpb = ();
	my %dbinfo = {};

	@tmpa = fileReadlines($path);
	exit(0) if(!$tmpa[0]);

	foreach(@tmpa) {
		if ( $_ !~ /[\s]*[#;]/ ) {
			$_ = $self->trim($_);
			@tmpb = split(/=/, $_);
			if ($tmpb[0] eq 'access_method') {
				$self->{access_method} = lc($tmpb[1]);
			} 
		}
	}

	@tmpa = (); @tmpb = ();

	# access_db_host = svn.dev.superlinuxer.com
	# access_db_name = svn
	# access_db_user = svn
	# access_db_password = svn_password
	if ($self->{access_method} eq 'db') {
		$path = $self->{repos} . '/conf/' . $self->{access_db};
		@tmpa = fileReadlines($path);
		foreach(@tmpa) {
			if ( $_ !~ /[\s]*[#;]/ ) {
				$_ = $self->trim($_);
				@tmpb = split(/=/, $_);
				$dbinfo{$tmpb[0]} = $tmpb[1];
			}
		}
		$self->{access_db_host} = $dbinfo{'access_db_host'};
		$self->{access_db_port} = $dbinfo{'access_db_port'};
		$self->{access_db_name} = $dbinfo{'access_db_name'};
		$self->{access_db_user} = $dbinfo{'access_db_user'};
		$self->{access_db_password} = $dbinfo{'access_db_password'};
	}

	return $self->{access_method};
}

sub Controller {
	my $self = shift if ref ($_[0]);
	my $access_method = $self->getAccessmethod();

	if ($access_method eq 'file') {
		$ACCESS->checkAnonymous();
		$ACCESS->getConfigFile();
		$ACCESS->checkPerms();
	} elsif ($access_method eq 'db') {
		$ACCESS->checkAnonymous();
		$ACCESS->getConfigDb();
		$ACCESS->checkPerms();
	} else {
		exit($FAIL);
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

#######################################
# DBI_MYSQL
#######################################
sub dbConnect {
	my $self = shift if ref ($_[0]);
	my $access_db_host = $_[0];
	my $access_db_port = $_[1];
	my $access_db_name = $_[2];
	my $access_db_user = $_[3];
	my $access_db_password = $_[4];

	$self->{dbh} = DBI->connect("DBI:mysql:database=$access_db_name;host=$access_db_host;port=$access_db_port", $access_db_user, $access_db_password);
}

sub dbQuery {
	my $self = shift if ref ($_[0]);
	my $query = $_[0];
	$self->{sth} = $self->{dbh}->prepare($query);
	$self->{sth}->execute;
	$self->{n_rows} = $self->{sth}->rows();
	$self->{n_fields} = $self->{sth}->{'NUM_OF_FIELDS'};
}

sub dbFetch {
	my $self = shift if ref ($_[0]);
	my $sfh =  $self->{sth}->fetchrow_hashref();
	$self->{sth}->finish() if (!$sfh);
	return $sfh;
}

sub dbFetchfinish {
	my $self = shift if ref ($_[0]);
	$self->{sth}->finish();
}

sub dbClose {
	my $self = shift if ref ($_[0]);
	#$self->{sth}->finish();
	$self->{dbh}->disconnect();
}

1;
