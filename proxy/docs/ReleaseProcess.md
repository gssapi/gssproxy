# Release Process for GSS-Proxy

The process is currently quite simple and requires write access to the
project's git repository.

# Prepare the sources

## Version and Tag the release

- Commit a change in version.m4 with the new version number (ex. 0.1.0)

- Test locally with "make rpms" that everything builds fine

- Tag the release in master like this:
```
git tag v0.1.0
```
  This will apply the tag to the last commit

- Push the tag:
```
git push origin v0.1.0
```

## Create a release tarball and SHA hash

- Run the following commands (on a git clean tree, please):
```
autoreconf -f -i
./configure
make dist
make distcheck
```
  ... will generate a tarball named like: gssproxy-0.1.0.tar.gz
```
sha512sum gssproxy-0.1.0.tar.gz > gssproxy-0.1.0.tar.gz.sha512sum.txt
```
  ... will generate a file with a sha512 checksum

## Publish the release

- Upload tarball and checksum to Pagure release page

- Create a Release page with highlights and a full changelog with the command:
```
git shortlog <oldtag>..<newtag>
```

- Copy the content of the new-release page into a mail and announce on the
  gssproxy mailinglist
  (https://lists.fedorahosted.org/mailman/listinfo/gss-proxy)
