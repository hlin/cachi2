from pathlib import Path
from unittest import mock
from urllib.parse import quote
import yaml

import pytest

from cachi2.core.errors import PackageManagerError, PackageRejected
from cachi2.core.models.sbom import Component
from cachi2.core.package_managers.rpm import fetch_rpm_source, inject_files_post
from cachi2.core.package_managers.rpm.main import (
    DEFAULT_LOCKFILE_NAME,
    DEFAULT_PACKAGE_DIR,
    _generate_sbom_components,
    _resolve_rpm_project,
    createrepo,
    generate_repos,
    generate_repofiles,
    download,
    verify_downloaded,
)
from cachi2.core.package_managers.rpm.redhat import RedhatRpmsLock
from cachi2.core.rooted_path import RootedPath


@pytest.fixture
def rooted_tmp_path(tmp_path: Path) -> RootedPath:
    return RootedPath(tmp_path)


RPM_LOCK_FILE_DATA = """
lockfileVersion: 1
lockfileVendor: redhat
arches:
  - arch: x86_64
    packages:
      - url: https://example.com/x86_64/Packages/v/vim-enhanced-9.1.158-1.fc38.x86_64.rpm
        checksum: sha256:21bb2a09852e75a693d277435c162e1a910835c53c3cee7636dd552d450ed0f1
        size: 1976132
        repoid: updates
    source:
      - url: https://example.com/source/tree/Packages/v/vim-9.1.158-1.fc38.src.rpm
        checksum: sha256:94803b5e1ff601bf4009f223cb53037cdfa2fe559d90251bbe85a3a5bc6d2aab
        size: 14735448
        repoid: updates-source
"""


@mock.patch("cachi2.core.package_managers.rpm.main.RequestOutput.from_obj_list")
@mock.patch("cachi2.core.package_managers.rpm.main._resolve_rpm_project")
def test_fetch_rpm_source(
    mock_resolve_rpm_project: mock.Mock,
    mock_from_obj_list: mock.Mock,
) -> None:
    mock_component = mock.Mock()
    mock_resolve_rpm_project.return_value = [mock_component]
    mock_request = mock.Mock()
    mock_request.rpm_packages = [mock.Mock()]
    fetch_rpm_source(mock_request)
    mock_resolve_rpm_project.assert_called_once()
    mock_from_obj_list.assert_called_once_with(
        components=[mock_component], environment_variables=[], project_files=[]
    )


def test_resolve_rpm_project_no_lockfile(rooted_tmp_path: RootedPath) -> None:
    with pytest.raises(PackageRejected) as exc_info:
        mock_source_dir = mock.Mock()
        mock_source_dir.join_within_root.return_value.path.exists.return_value = False
        _resolve_rpm_project(mock_source_dir, mock.Mock())
    assert f"Rpm lockfile '{DEFAULT_LOCKFILE_NAME}' missing, refusing to continue" in str(
        exc_info.value
    )


@mock.patch(
    "cachi2.core.package_managers.rpm.main.open",
    new_callable=mock.mock_open,
    read_data="&",
)
def test_resolve_rpm_project_invalid_yaml_format(mock_open) -> None:
    with pytest.raises(PackageRejected) as exc_info:
        _resolve_rpm_project(mock.Mock(), mock.Mock())
    assert f"Rpm lockfile '{DEFAULT_LOCKFILE_NAME}' yaml format is not correct" in str(
        exc_info.value
    )


@mock.patch(
    "cachi2.core.package_managers.rpm.main.open",
    new_callable=mock.mock_open,
    read_data="invalid: lockfile format",
)
def test_resolve_rpm_project_invalid_lockfile_format(mock_open) -> None:
    with pytest.raises(PackageManagerError) as exc_info:
        _resolve_rpm_project(mock.Mock(), mock.Mock())
    assert f"Rpm lockfile '{DEFAULT_LOCKFILE_NAME}' format is not valid" in str(exc_info.value)


@mock.patch(
    "cachi2.core.package_managers.rpm.main.open",
    new_callable=mock.mock_open,
)
@mock.patch("cachi2.core.package_managers.rpm.main.download")
@mock.patch("cachi2.core.package_managers.rpm.main.verify_downloaded")
@mock.patch("cachi2.core.package_managers.rpm.main.RedhatRpmsLock.from_yaml")
@mock.patch("cachi2.core.package_managers.rpm.main._generate_sbom_components")
def test_resolve_rpm_project(
    mock_generate_sbom_components: mock.Mock,
    mock_from_yaml: mock.Mock,
    mock_verify_downloaded: mock.Mock,
    mock_download: mock.Mock,
    mock_open: mock.Mock,
) -> None:
    # mock_redhat_rpms_lock = mock_from_yaml.return_value
    output_dir = mock.Mock()
    mock_package_dir_path = mock.Mock()
    output_dir.join_within_root.return_value.path = mock_package_dir_path
    _resolve_rpm_project(mock.Mock(), output_dir)
    mock_download.assert_called_once_with(mock_from_yaml.return_value, mock_package_dir_path)
    mock_verify_downloaded.assert_called_once_with(mock_from_yaml.return_value)
    mock_generate_sbom_components.assert_called_once_with(mock_from_yaml.return_value.metadata)


@mock.patch("cachi2.core.package_managers.rpm.main.run_cmd")
def test_createrepo(mock_run_cmd: mock.Mock, rooted_tmp_path: RootedPath) -> None:
    repodir = str(rooted_tmp_path)
    repoid = "repo1"
    createrepo(repoid, repodir)
    mock_run_cmd.assert_called_once_with(["createrepo_c", repodir], params={})


@mock.patch("cachi2.core.package_managers.rpm.main.createrepo")
def test_generate_repos(mock_createrepo, rooted_tmp_path) -> None:
    package_dir = rooted_tmp_path.join_within_root(DEFAULT_PACKAGE_DIR)
    arch_dir = package_dir.path.joinpath("x86_64")
    arch_dir.joinpath("repo1").mkdir(parents=True)
    arch_dir.joinpath("repos.d").mkdir(parents=True)
    generate_repos(rooted_tmp_path.path)
    mock_createrepo.assert_called_once_with("repo1", arch_dir.joinpath("repo1"))


def test_generate_repofiles(rooted_tmp_path: RootedPath) -> None:
    package_dir = rooted_tmp_path.join_within_root(DEFAULT_PACKAGE_DIR)
    arch_dir = package_dir.path.joinpath("x86_64")
    arch_dir.joinpath("repo1").mkdir(parents=True)
    arch_dir.joinpath("cachi2-repo2").mkdir(parents=True)
    arch_dir.joinpath("repos.d").mkdir(parents=True)
    repopath = arch_dir.joinpath("repos.d", "cachi2.repo")
    output_dir = f"{package_dir}/x86_64"
    name = (
        "name=Generated repository containing all packages unaffiliated "
        "with any official repository"
    )
    template = f"[repo1]\nbaseurl=file://{output_dir}/repo1\ngpgcheck=1\n[cachi2-repo2]\nbaseurl=file://{output_dir}/cachi2-repo2\ngpgcheck=1\n{name}"
    generate_repofiles(rooted_tmp_path.path, rooted_tmp_path.path)
    with open(repopath) as f:
        assert template == f.read()


@mock.patch("cachi2.core.package_managers.rpm.main.run_cmd")
def test_generate_sbom_components(mock_run_cmd) -> None:
    vender = "redhat"
    name = "foo"
    version = "1.0"
    release = "2.fc39"
    arch = "x86_64"
    vendor = "redhat"
    epoch = ""
    mock_run_cmd.return_value = f"{name}\n{version}\n{release}\n{arch}\n{vendor}\n{epoch}"
    rpm = f"{name}-{version}-{release}.{arch}.rpm"
    url = f"https://example.com/{rpm}"
    files_metadata = {
        Path(f"/path/to/{rpm}"): {
            "package": True,
            "url": url,
            "size": 12345,
            "checksum": "sha256:21bb2a09852e75a693d277435c162e1a910835c53c3cee7636dd552d450ed0f1",
        }
    }
    components = _generate_sbom_components(files_metadata)
    assert components == [
        Component(
            name=name,
            version=version,
            purl=f"pkg:rpm/{vender}/{name}@{version}-{release}?arch={arch}&download_url={quote(url)}",
        )
    ]


@mock.patch("cachi2.core.package_managers.rpm.main.Path")
@mock.patch("cachi2.core.package_managers.rpm.main.generate_repofiles")
@mock.patch("cachi2.core.package_managers.rpm.main.generate_repos")
def test_inject_files_post(
    mock_generate_repos: mock.Mock,
    mock_generate_repofiles: mock.Mock,
    mock_path: mock.Mock,
    rooted_tmp_path: RootedPath,
) -> None:
    inject_files_post(from_output_dir=rooted_tmp_path.path, for_output_dir=rooted_tmp_path.path)
    mock_generate_repos.assert_called_once_with(rooted_tmp_path.path)
    mock_generate_repofiles.assert_called_with(rooted_tmp_path.path, rooted_tmp_path.path)


@mock.patch("cachi2.core.package_managers.rpm.main.asyncio.run")
@mock.patch("cachi2.core.package_managers.rpm.main.async_download_files")
def test_download(
    mock_async_download_files: mock.Mock, mock_asyncio: mock.Mock, rooted_tmp_path: RootedPath
) -> None:
    lock = RedhatRpmsLock.from_yaml(yaml.safe_load(RPM_LOCK_FILE_DATA))
    download(lock, rooted_tmp_path.path)
    mock_async_download_files.assert_called_once_with(
        {
            "https://example.com/x86_64/Packages/v/vim-enhanced-9.1.158-1.fc38.x86_64.rpm": str(
                rooted_tmp_path.path.joinpath(
                    "x86_64/updates/vim-enhanced-9.1.158-1.fc38.x86_64.rpm"
                )
            ),
            "https://example.com/source/tree/Packages/v/vim-9.1.158-1.fc38.src.rpm": str(
                rooted_tmp_path.path.joinpath("x86_64/updates-source/vim-9.1.158-1.fc38.src.rpm")
            ),
        },
        5,
    )
    mock_asyncio.assert_called_once()


def test_verify_downloaded_unexpected_size() -> None:
    lockfile = mock.Mock()
    lockfile.metadata = {mock.Mock(): {"size": 12345}}
    with pytest.raises(PackageRejected) as exc_info:
        verify_downloaded(lockfile)
    assert "Unexpected file size of" in str(exc_info.value)


def test_verify_downloaded_unsupported_hash_alg() -> None:
    lockfile = mock.Mock()
    lockfile.metadata = {mock.Mock(): {"checksum": "noalg:unmatchedchecksum", "size": None}}
    with pytest.raises(PackageRejected) as exc_info:
        verify_downloaded(lockfile)
    assert "Unsupported hashing algorithm" in str(exc_info.value)


@mock.patch(
    "cachi2.core.package_managers.rpm.main.open",
    new_callable=mock.mock_open,
    read_data=b"test",
)
def test_verify_downloaded_unmatched_checksum(mock_open) -> None:
    lockfile = mock.Mock()
    lockfile.metadata = {mock.Mock(): {"checksum": "sha256:unmatchedchecksum", "size": None}}
    with pytest.raises(PackageRejected) as exc_info:
        verify_downloaded(lockfile)
    assert "Unmatched checksum of" in str(exc_info.value)


class TestRedhatRpmsLock:
    @pytest.fixture
    def raw_content(self):
        return {"lockfileVendor": "redhat", "lockfileVersion": 1, "arches": []}

    def test_match_format(self, raw_content: dict) -> None:
        lock = RedhatRpmsLock.from_yaml(raw_content)
        assert lock.match_format() is True

    @mock.patch("cachi2.core.package_managers.rpm.redhat.uuid")
    def test_internal_repoid(self, mock_uuid, raw_content: dict) -> None:
        mock_uuid.uuid4.return_value.hex = "abcdefghijklmn"
        lock = RedhatRpmsLock.from_yaml(raw_content)
        assert lock._uuid == "abcdef"
        assert lock.internal_repoid == "cachi2-abcdef"

    @mock.patch("cachi2.core.package_managers.rpm.redhat.uuid")
    def test_internal_source_repoid(self, mock_uuid, raw_content: dict) -> None:
        mock_uuid.uuid4.return_value.hex = "abcdefghijklmn"
        lock = RedhatRpmsLock.from_yaml(raw_content)
        assert lock._uuid == "abcdef"
        assert lock.internal_source_repoid == "cachi2-abcdef-source"

    def test_uuid(self, raw_content: dict) -> None:
        lock = RedhatRpmsLock.from_yaml(raw_content)
        uuid = lock._uuid
        assert len(uuid) == 6
