# permitd

Permitd is a Linux daemon which enforces permissions on a directory tree.

On SSH based fileservers it can happen that files on a share still have
user specific permissions so other users can't access them.
*permitd* monitors the whole directory tree of configured paths with
inotify and sets the correct permissions on every event.

## Installation

The recommended way to install *permitd* is to use the Debian package built
with `cargo deb`. This will install all files (binary, main config,
logrotate config and systemd unit) to the correct locations.

## Building

The build process uses cargo as top level build system to build the rust
components. To build the debian package, the "cargo-deb" plugin is required.
It can be installed with `cargo install cargo-deb`.

## Configuration

Add a *[[dir]]* block for every monitored directory tree to the *permitd.conf*
file. The following options are available:

* *path*: The root of the directory tree to monitor.
* *unix*: Unix file permissions in "owner:group octal\_mode" format.
* *acl*: An optional ACL in *setfacl* format.

If lots of directories are watched, it can happen that permitd fails with
"No space left on device" during startup. In this case, it is necessary to
increase the inotify limit by adding "fs.inotify.max\_user\_watches=XXX" to
*/etc/sysctl.conf*. The current limit can be retrieved by executing
`cat /proc/sys/fs/inotify/max\_user\_watches`.

## License

*permitd* is licensed under the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or (at your
option) any later version.
