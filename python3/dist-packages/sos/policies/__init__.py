
import logging
import os
import platform
import time
import json
import tempfile
import random
import string
import sys

from pwd import getpwuid
from textwrap import fill
from sos.presets import (NO_PRESET, GENERIC_PRESETS, PRESETS_PATH,
                         PresetDefaults, DESC, NOTE, OPTS)
from sos.policies.package_managers import PackageManager
from sos.utilities import (ImporterHelper, import_module, get_human_readable,
                           bold)
from sos.report.plugins import IndependentPlugin, ExperimentalPlugin
from sos.options import SoSOptions
from sos import _sos as _


def import_policy(name):
    policy_fqname = f"sos.policies.distros.{name}"
    try:
        return import_module(policy_fqname, Policy)
    except ImportError:
        return None


def load(cache={}, sysroot=None, init=None, probe_runtime=True,
         remote_exec=None, remote_check=''):
    if 'policy' in cache:
        return cache.get('policy')

    import sos.policies.distros
    helper = ImporterHelper(sos.policies.distros)
    for module in helper.get_modules():
        for policy in import_policy(module):
            if policy.check(remote=remote_check):
                cache['policy'] = policy(sysroot=sysroot, init=init,
                                         probe_runtime=probe_runtime,
                                         remote_exec=remote_exec)

    if sys.platform != 'linux':
        raise Exception("SoS is not supported on this platform")

    if 'policy' not in cache:
        cache['policy'] = sos.policies.distros.GenericLinuxPolicy()

    return cache['policy']


class Policy():
    """Policies represent distributions that sos supports, and define the way
    in which sos behaves on those distributions. A policy should define at
    minimum a way to identify the distribution, and a package manager to allow
    for package based plugin enablement.

    Policies also control preferred ContainerRuntime()'s, upload support to
    default locations for distribution vendors, disclaimer text, and default
    presets supported by that distribution or vendor's products.

    Every Policy will also need at least one "tagging class" for plugins.

    :param sysroot: Set the sysroot for the system, if not /
    :type sysroot: ``str`` or ``None``

    :param probe_runtime: Should the Policy try to load a ContainerRuntime
    :type probe_runtime: ``bool``

    :param remote_exec:     If this policy is loaded for a remote node, use
                            this to facilitate executing commands via the
                            SoSTransport in use
    :type remote_exec:      ``SoSTranport.run_command()``

    :cvar distro: The name of the distribution the Policy represents
    :vartype distro: ``str``

    :cvar vendor: The name of the vendor producing the distribution
    :vartype vendor: ``str``

    :cvar vendor_urls: List of URLs for the vendor's website, or support portal
    :vartype vendor_urls: ``list`` of ``tuples`` formatted
        ``(``description``, ``url``)``

    :cvar vendor_text: Additional text to add to the banner message
    :vartype vendor_text: ``str``

    :cvar name_pattern: The naming pattern to be used for naming archives
                        generated by sos. Values of `legacy`, and `friendly`
                        are preset patterns. May also be set to an explicit
                        custom pattern, see `get_archive_name()`
    :vartype name_pattern: ``str``
    """

    msg = _("""\
This command will collect system configuration and diagnostic information \
from this %(distro)s system.

For more information on %(vendor)s visit:

  %(vendor_urls)s

The generated archive may contain data considered sensitive and its content \
should be reviewed by the originating organization before being passed to \
any third party.

%(changes_text)s

%(vendor_text)s
""")

    distro = "Unknown"
    vendor = "Unknown"
    vendor_urls = [('Example URL', "http://www.example.com/")]
    vendor_text = ""
    PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    name_pattern = 'legacy'
    presets = {"": PresetDefaults()}
    presets_path = PRESETS_PATH
    _in_container = False

    def __init__(self, sysroot=None, probe_runtime=True, remote_exec=None):
        """Subclasses that choose to override this initializer should call
        super() to ensure that they get the required platform bits attached.
        super(SubClass, self).__init__(). Policies that require runtime
        tests to construct PATH must call self.set_exec_path() after
        modifying PATH in their own initializer."""
        self.soslog = logging.getLogger('sos')
        self.ui_log = logging.getLogger('sos_ui')
        self._parse_uname()
        self.case_id = None
        self.probe_runtime = probe_runtime
        self.package_manager = PackageManager()
        self.valid_subclasses = [IndependentPlugin]
        self.remote_exec = remote_exec
        if not self.remote_exec:
            self.set_exec_path()
        self.sysroot = sysroot
        self.register_presets(GENERIC_PRESETS)

    def check(self, remote=''):
        """
        This function is responsible for determining if the underlying system
        is supported by this policy.

        If `remote` is provided, it should be the contents of os-release from
        a remote host, or a similar vendor-specific file that can be used in
        place of a locally available file.

        :returns: ``True`` if the Policy should be loaded, else ``False``
        :rtype: ``bool``
        """
        return False

    @property
    def forbidden_paths(self):
        """This property is used to determine the list of forbidden paths
        set by the policy. Note that this property will construct a
        *cumulative* list based on all subclasses of a given policy.

        :returns: All patterns of policy forbidden paths
        :rtype: ``list``
        """
        if not hasattr(self, '_forbidden_paths'):
            self._forbidden_paths = []
            for cls in self.__class__.__mro__:
                if hasattr(cls, 'set_forbidden_paths'):
                    self._forbidden_paths.extend(cls.set_forbidden_paths())
        return list(set(self._forbidden_paths))

    @classmethod
    def set_forbidden_paths(cls):
        """Use this to *append* policy-specifc forbidden paths that apply to
        all plugins. Setting this classmethod on an invidual policy will *not*
        override subclass-specific paths
        """
        return [
            '*.egg',
            '*.pyc',
            '*.pyo',
            '*.swp'
        ]

    def in_container(self):
        """Are we running inside a container?

        :returns: ``True`` if in a container, else ``False``
        :rtype: ``bool``
        """
        return self._in_container

    def dist_version(self):
        """
        Return the OS version
        """
        pass

    def get_preferred_archive(self):
        """
        Return the class object of the prefered archive format for this
        platform
        """
        from sos.archive import TarFileArchive
        return TarFileArchive

    def get_archive_name(self):
        """
        This function should return the filename of the archive without the
        extension.

        This uses the policy's `name_pattern` attribute to determine the name.
        There are two pre-defined naming patterns - `legacy` and `friendly`
        that give names like the following:

        * legacy - `sosreport-tux.123456-20171224185433`
        * friendly - `sosreport-tux-mylabel-123456-2017-12-24-ezcfcop.tar.xz`

        A custom name_pattern can be used by a policy provided that it
        defines name_pattern using a format() style string substitution.

        Usable substitutions are:

            * name  - the short hostname of the system
            * label - the label given by --label
            * case  - the case id given by --case-id
            * rand  - a random string of 7 alpha characters

        Note that if a datestamp is needed, the substring should be set
        in `name_pattern` in the format accepted by ``strftime()``.

        :returns: A name to be used for the archive, as expanded from
                  the Policy `name_pattern`
        :rtype: ``str``
        """
        name = self.get_local_name().split('.')[0]  # pylint: disable=no-member
        case = self.case_id
        label = self.commons['cmdlineopts'].label
        date = ''
        rand = ''.join(random.choice(string.ascii_lowercase) for x in range(7))

        if self.name_pattern == 'legacy':
            case = '.' + case if case else ''
            date = '-%Y%m%d%H%M%S'
            nstr = f"sosreport-{name}{case}{date}"
        elif self.name_pattern == 'friendly':
            case = '-' + case if case else ''
            label = '-' + label if label else ''
            date = '-%Y-%m-%d'
            nstr = f"sosreport-{name}{label}{case}{date}-{rand}"
        else:
            nstr = self.name_pattern

        # pylint: disable-next=no-member
        return self.sanitize_filename(time.strftime(nstr))

    # for some specific binaries like "xz", we need to determine package
    # providing it; that is policy specific. By default return the binary
    # name itself until particular policy overwrites it
    def _get_pkg_name_for_binary(self, binary):
        return binary

    def get_tmp_dir(self, opt_tmp_dir):
        if not opt_tmp_dir:
            return tempfile.gettempdir()
        return opt_tmp_dir

    def match_plugin(self, plugin_classes):
        """Determine what subclass of a Plugin should be used based on the
        tagging classes assigned to the Plugin

        :param plugin_classes: The classes that the Plugin subclasses
        :type plugin_classes: ``list``

        :returns: The first tagging class that matches one of the Policy's
                  `valid_subclasses`
        :rtype: ``PluginDistroTag``
        """
        if len(plugin_classes) > 1:
            for p in plugin_classes:
                # Give preference to the first listed tagging class
                # so that e.g. UbuntuPlugin is chosen over DebianPlugin
                # on an Ubuntu installation.
                if issubclass(p, self.valid_subclasses[0]):
                    return p
        return plugin_classes[0]

    def validate_plugin(self, plugin_class, experimental=False):
        """
        Verifies that the plugin_class should execute under this policy

        :param plugin_class: The tagging class being checked
        :type plugin_class: ``PluginDistroTag``

        :returns: ``True`` if the `plugin_class` is allowed by the policy
        :rtype: ``bool``
        """
        valid_subclasses = [IndependentPlugin] + self.valid_subclasses
        if experimental:
            valid_subclasses += [ExperimentalPlugin]
        return any(issubclass(plugin_class, class_) for
                   class_ in valid_subclasses)

    def pre_work(self):
        """
        This function is called prior to collection.
        """
        pass

    def post_work(self):
        """
        This function is called after the sosreport has been generated.
        """
        pass

    def pkg_by_name(self, pkg):
        """Wrapper to retrieve a package from the Policy's package manager

        :param pkg: The name of the package
        :type pkg: ``str``

        :returns: The first package that matches `pkg`
        :rtype: ``str``
        """
        return self.package_manager.pkg_by_name(pkg)

    def _parse_uname(self):
        (system, node, release,
         version, machine, processor) = platform.uname()
        self.system = system
        self.hostname = node
        self.release = release
        self.smp = version.split()[1] == "SMP"
        self.machine = machine

    def set_commons(self, commons):
        """Set common host data for the Policy to reference
        """
        self.commons = commons

    def _set_PATH(self, path):
        os.environ['PATH'] = path

    def set_exec_path(self):
        self._set_PATH(self.PATH)

    def is_root(self):
        """This method should return true if the user calling the script is
        considered to be a superuser

        :returns: ``True`` if user is superuser, else ``False``
        :rtype: ``bool``
        """
        return (os.getuid() == 0)

    def get_preferred_hash_name(self):
        """Returns the string name of the hashlib-supported checksum algorithm
        to use"""
        return "sha256"

    @classmethod
    def display_help(cls, section):
        section.set_title('SoS Policies')
        section.add_text(
            'Policies help govern how SoS operates on across different distri'
            'butions of Linux. They control aspects such as plugin enablement,'
            ' $PATH determination, how/which package managers are queried, '
            'default upload specifications, and more.'
        )

        section.add_text(
            "When SoS intializes most functions, for example "
            f"{bold('sos report')} and {bold('sos collect')}, one "
            "of the first operations is to determine the correct policy to "
            "load for the local system. Policies will determine the proper "
            "package manager to use, any applicable container runtime(s), and "
            "init systems so that SoS and report plugins can properly function"
            " for collections. Generally speaking a single policy will map to"
            " a single distribution; for example there are separate policies "
            "for Debian, Ubuntu, RHEL, and Fedora."
        )

        section.add_text(
            "It is currently not possible for users to directly control which "
            "policy is loaded."
        )

        pols = {
            'policies.cos': 'The Google Cloud-Optimized OS distribution',
            'policies.debian': 'The Debian distribution',
            'policies.redhat': ('Red Hat family distributions, not necessarily'
                                ' including forks'),
            'policies.ubuntu': 'Ubuntu/Canonical distributions'
        }

        seealso = section.add_section('See Also')
        seealso.add_text(
            "For more information on distribution policies, see below\n"
        )
        for pol in pols:
            seealso.add_text(
                f"{' ':>8}{pol:<20}{pols[pol]:<30}",
                newline=False
            )

    def display_results(self, archive, directory, checksum, archivestat=None,
                        map_file=None):
        """Display final information about a generated archive

        :param archive: The name of the archive that was generated
        :type archive: ``str``

        :param directory: The build directory for sos if --build was used
        :type directory: ``str``

        :param checksum: The checksum of the archive
        :type checksum: ``str``

        :param archivestat: stat() information for the archive
        :type archivestat: `os.stat_result`

        :param map_file: If sos clean was invoked, the location of the mapping
                         file for this run
        :type map_file: ``str``
        """
        # Logging is shut down, but there are some edge cases where automation
        # does not capture printed output (e.g. avocado CI). Use the ui_log to
        # still print to console in this case.

        # make sure a report exists
        if not archive and not directory:
            return False

        if map_file:
            self.ui_log.info(
                _(f"\nA mapping of obfuscated elements is available at"
                  f"\n\t{map_file}")
            )

        if archive:
            self.ui_log.info(
                _(f"\nYour sosreport has been generated and saved in:"
                  f"\n\t{archive}\n")
            )
            self.ui_log.info(
                _(f" Size\t{get_human_readable(archivestat.st_size)}")
            )
            self.ui_log.info(
                _(f" Owner\t{getpwuid(archivestat.st_uid).pw_name}")
            )
        else:
            self.ui_log.info(
                _(f"Your sosreport build tree has been generated in:"
                  f"\n\t{directory}\n")
            )
        if checksum:
            self.ui_log.info(f" {self.get_preferred_hash_name()}\t{checksum}")
            self.ui_log.info(
                _("\nPlease send this file to your support representative.\n")
            )
        return None

    def get_msg(self):
        """This method is used to prepare the preamble text to display to
        the user in non-batch mode. If your policy sets self.distro that
        text will be substituted accordingly. You can also override this
        method to do something more complicated.

        :returns: Formatted banner message string
        :rtype: ``str``
        """
        if self.commons['cmdlineopts'].allow_system_changes:
            changes_text = "Changes CAN be made to system configuration."
        else:
            changes_text = "No changes will be made to system configuration."
        width = 72
        _msg = self.msg % {'distro': self.distro, 'vendor': self.vendor,
                           'vendor_urls': self._fmt_vendor_urls(),
                           'vendor_text': self.vendor_text,
                           'tmpdir': self.commons['tmpdir'],
                           'changes_text': changes_text}
        _fmt = ""
        for line in _msg.splitlines():
            _fmt = _fmt + fill(line, width, replace_whitespace=False) + '\n'
        return _fmt

    def _fmt_vendor_urls(self):
        """Formats all items in the ``vendor_urls`` class attr into a usable
        string for the banner message.

        :returns:   Formatted string of URLS
        :rtype:     ``str``
        """
        width = max([len(v[0]) for v in self.vendor_urls])
        return "\n".join(
            f"\t{url[0]:<{width}} : {url[1]}" for url in self.vendor_urls
        )

    def register_presets(self, presets, replace=False):
        """Add new presets to this policy object.

            Merges the presets dictionary ``presets`` into this ``Policy``
            object, or replaces the current presets if ``replace`` is
            ``True``.

            ``presets`` should be a dictionary mapping ``str`` preset names
            to ``<class PresetDefaults>`` objects specifying the command
            line defaults.

            :param presets: dictionary of presets to add or replace
            :param replace: replace presets rather than merge new presets.
        """
        if replace:
            self.presets = {}
        self.presets.update(presets)

    def find_preset(self, preset):
        """Find a preset profile matching the specified preset string.

            :param preset: a string containing a preset profile name.
            :returns: a matching PresetProfile.
        """
        # FIXME: allow fuzzy matching?
        for match in self.presets.keys():
            if match == preset:
                return self.presets[match]

        return None

    def probe_preset(self):
        """Return a ``PresetDefaults`` object matching the runing host.

            Stub method to be implemented by derived policy classes.

            :returns: a ``PresetDefaults`` object.
        """
        return self.presets[NO_PRESET]

    def load_presets(self, presets_path=None):
        """Load presets from disk.

            Read JSON formatted preset data from the specified path,
            or the default location at ``/var/lib/sos/presets``.

            :param presets_path: a directory containing JSON presets.
        """
        presets_path = presets_path or self.presets_path
        if not os.path.exists(presets_path):
            return
        for preset_path in os.listdir(presets_path):
            preset_path = os.path.join(presets_path, preset_path)

            with open(preset_path) as pf:
                try:
                    preset_data = json.load(pf)
                except ValueError:
                    continue

            for preset in preset_data.keys():
                pd = PresetDefaults(preset, opts=SoSOptions())
                data = preset_data[preset]
                pd.desc = data[DESC] if DESC in data else ""
                pd.note = data[NOTE] if NOTE in data else ""

                if OPTS in data:
                    for arg in data[OPTS]:
                        setattr(pd.opts, arg, data[OPTS][arg])
                pd.builtin = False
                self.presets[preset] = pd

    def add_preset(self, name=None, desc=None, note=None, opts=SoSOptions()):
        """Add a new on-disk preset and write it to the configured
            presets path.

            :param preset: the new PresetDefaults to add
        """
        presets_path = self.presets_path

        if not name:
            raise ValueError("Preset name cannot be empty")

        if name in self.presets.keys():
            raise ValueError(f"A preset with name '{name}' already exists")

        preset = PresetDefaults(name=name, desc=desc, note=note, opts=opts)
        preset.builtin = False
        self.presets[preset.name] = preset
        preset.write(presets_path)

    def del_preset(self, name=""):
        if not name or name not in self.presets.keys():
            raise ValueError(f"Unknown profile: '{name}'")

        preset = self.presets[name]

        if preset.builtin:
            raise ValueError(f"Cannot delete built-in preset '{preset.name}'")

        preset.delete(self.presets_path)
        self.presets.pop(name)


# vim: set et ts=4 sw=4 :