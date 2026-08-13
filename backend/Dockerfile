# QLint backend image.
#
# The reason this file exists is liboqs. pqc_benchmark.py needs the liboqs C
# library in the process, and on Windows there is no way to get it -- which is
# why the PQC Benchmark Lab has so far only worked when the backend was
# launched from WSL. Here liboqs is compiled once, at image build time, into a
# Linux image. The container that eventually runs has no compiler, no git and
# no network requirement: the shared library is simply already there.
#
# Two stages, because the toolchain that builds liboqs (cmake, gcc, the full
# liboqs source tree) is several hundred megabytes that the running service has
# no use for. Stage 1 builds, stage 2 keeps only the artefacts.

# ---------------------------------------------------------------- stage 1 ---
# 3.13 matches the interpreter the project is developed against (backend/.venv
# is 3.13.9).
FROM python:3.13-slim AS builder

# cmake + build-essential compile liboqs, git fetches it, libssl-dev is
# liboqs's optional OpenSSL backend (it uses OpenSSL for symmetric primitives
# and RNG). ninja is not required -- the default Make generator is fine and one
# fewer package to install.
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        cmake \
        git \
        libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Python dependencies first, and in their own layer: they change far less often
# than application code, so an edit to a scanner does not re-run pip.
#
# requirements-pqc.txt is the file that carries liboqs-python. It is kept
# separate from requirements.txt precisely so a Windows-native setup can skip
# it; in this image it is exactly what we want, so both are installed.
COPY requirements.txt requirements-pqc.txt ./
RUN pip install --no-cache-dir -r requirements.txt -r requirements-pqc.txt

# Build liboqs at the version the installed liboqs-python binding expects,
# rather than a hardcoded tag: the two projects release in lockstep, and the
# binding refuses to run against a C library whose minor version it does not
# recognise. Asking the binding which version it is pins the pair together
# automatically, so bumping requirements-pqc.txt cannot silently desync them.
#
# -DBUILD_SHARED_LIBS=ON  -> liboqs.so, which is what the ctypes binding loads
# -DOQS_BUILD_ONLY_LIB=ON -> skip liboqs's tests and speed benchmarks
# -DOQS_DIST_BUILD=ON     -> runtime CPU feature detection instead of building
#                            for the CPU of whatever machine built the image,
#                            so the image is portable off this laptop
RUN LIBOQS_VERSION="$(python -c 'import importlib.metadata as m; print(m.version("liboqs-python"))')" \
    && echo "Building liboqs ${LIBOQS_VERSION} to match liboqs-python ${LIBOQS_VERSION}" \
    && git clone --depth 1 --branch "${LIBOQS_VERSION}" \
        https://github.com/open-quantum-safe/liboqs.git /build/liboqs \
    && cmake -S /build/liboqs -B /build/liboqs/build \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX=/usr/local \
        -DBUILD_SHARED_LIBS=ON \
        -DOQS_BUILD_ONLY_LIB=ON \
        -DOQS_DIST_BUILD=ON \
    && cmake --build /build/liboqs/build --parallel "$(nproc)" \
    && cmake --install /build/liboqs/build \
    && ldconfig \
    && rm -rf /build/liboqs

# Stage the library into a directory of its own for stage 2 to pick up whole.
#
# This looks like an unnecessary hop, and it is load-bearing. `cmake --install`
# lays down one real 27 MB file (liboqs.so.0.16.0) plus two symlinks to it
# (liboqs.so.9, liboqs.so). A wildcard COPY --from resolves each match, so it
# would write three real 27 MB files into the runtime image -- 55 MB of
# duplicate library. Copying a *directory* preserves symlinks as symlinks, and
# `cp -a` keeps them intact on the way in. The version number never has to be
# named, which matters because the version is whatever the binding asked for.
RUN mkdir -p /opt/liboqs && cp -a /usr/local/lib/liboqs.so* /opt/liboqs/

# Fail the build here rather than at the first user click if the pairing above
# is wrong. This also proves the library is loadable from the standard search
# path -- if it were not, the binding would quietly clone and build its own
# copy into $HOME, which is the runtime download this whole file exists to
# avoid, and that copy would not survive into stage 2.
RUN python -c "\
import os, oqs;\
lib = oqs.native()._name;\
assert lib.startswith('/usr/local/lib') or 'liboqs' in lib, lib;\
assert not os.path.exists(os.path.expanduser('~/_oqs')), 'liboqs was auto-installed at build time';\
kem = oqs.KeyEncapsulation('ML-KEM-768');\
print('liboqs', oqs.oqs_version(), 'loaded from', lib);\
print('ML-KEM-768 public key length:', len(kem.generate_keypair()), 'bytes')"

# ---------------------------------------------------------------- stage 2 ---
FROM python:3.13-slim AS runtime

# No compiler, no cmake, no git, no liboqs sources -- only the two things the
# builder produced: the shared library and the installed site-packages.
COPY --from=builder /opt/liboqs/ /usr/local/lib/
COPY --from=builder /usr/local/lib/python3.13/site-packages \
                    /usr/local/lib/python3.13/site-packages

# Refresh the loader cache so ctypes.util.find_library("oqs") resolves. Without
# this the binding would fall back to downloading and building its own liboqs
# on first import, in a container that has no toolchain to do it with.
RUN ldconfig

# Unbuffered stdout/stderr: uvicorn's startup lines and the app's WARNING about
# an unreachable MongoDB have to appear in `docker logs` as they happen, not
# when a 4 KB pipe buffer happens to fill.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app
COPY . .

# Drop privileges. The home directory is real and owned by the user so that
# nothing in the stack falls over trying to write a cache into a read-only
# home -- but note that liboqs is loaded from /usr/local/lib, not from here.
RUN useradd --create-home --uid 1000 qlint && chown -R qlint:qlint /app
USER qlint

EXPOSE 8000

# Production shape, unlike the README's dev command: no --reload (it would
# watch the filesystem and restart on nothing), bound to 0.0.0.0 so the port
# publish reaches it, and two workers.
#
# Two rather than the usual (2 x cores) + 1: /benchmark/run is seconds of
# deliberately CPU-saturating cryptography, so extra workers would compete for
# the same cores and make every concurrent benchmark slower and less accurate.
# Two keeps the API responsive while one worker is busy measuring.
CMD ["python", "-m", "uvicorn", "main:app", \
     "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]
