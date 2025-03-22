use crate::nfs::*;
use crate::nfs;
use async_trait::async_trait;
use std::cmp::Ordering;
use std::sync::Once;
use std::time::SystemTime;
use crate::rpc::auth_unix;

#[derive(Default, Debug)]
pub struct DirEntrySimple {
    pub fileid: fileid3,
    pub name: filename3,
}
#[derive(Default, Debug)]
pub struct ReadDirSimpleResult {
    pub entries: Vec<DirEntrySimple>,
    pub end: bool,
}

#[derive(Default, Debug)]
pub struct DirEntry {
    pub fileid: fileid3,
    pub name: filename3,
    pub attr: fattr3,
}
#[derive(Default, Debug)]
pub struct ReadDirResult {
    pub entries: Vec<DirEntry>,
    pub end: bool,
}

impl ReadDirSimpleResult {
    fn from_readdir_result(result: &ReadDirResult) -> ReadDirSimpleResult {
        let entries: Vec<DirEntrySimple> = result
            .entries
            .iter()
            .map(|e| DirEntrySimple {
                fileid: e.fileid,
                name: e.name.clone(),
            })
            .collect();
        ReadDirSimpleResult {
            entries,
            end: result.end,
        }
    }
}

static mut GENERATION_NUMBER: u64 = 0;
static GENERATION_NUMBER_INIT: Once = Once::new();

fn get_generation_number() -> u64 {
    unsafe {
        GENERATION_NUMBER_INIT.call_once(|| {
            GENERATION_NUMBER = SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64;
        });
        GENERATION_NUMBER
    }
}

/// What capabilities are supported
pub enum VFSCapabilities {
    ReadOnly,
    ReadWrite,
}

/// The basic API to implement to provide an NFS file system
///
/// Opaque FH
/// ---------
/// Files are only uniquely identified by a 64-bit file id. (basically an inode number)
/// We automatically produce internally the opaque filehandle which is comprised of
///  - A 64-bit generation number derived from the server startup time
///   (i.e. so the opaque file handle expires when the NFS server restarts)
///  - The 64-bit file id
//
/// readdir pagination
/// ------------------
/// We do not use cookie verifier. We just use the start_after.  The
/// implementation should allow startat to start at any position. That is,
/// the next query to readdir may be the last entry in the previous readdir
/// response.
//
/// There is a wierd annoying thing about readdir that limits the number
/// of bytes in the response (instead of the number of entries). The caller
/// will have to truncate the readdir response / issue more calls to readdir
/// accordingly to fill up the expected number of bytes without exceeding it.
//
/// Other requirements
/// ------------------
///  getattr needs to be fast. NFS uses that a lot
//
///  The 0 fileid is reserved and should not be used
///
#[async_trait]
pub trait NFSFileSystem: Sync {
    /// Returns the set of capabilities supported
    fn capabilities(&self) -> VFSCapabilities;
    /// Returns the ID the of the root directory "/"
    fn root_dir(&self) -> fileid3;
    /// Look up the id of a path in a directory
    ///
    /// i.e. given a directory dir/ containing a file a.txt
    /// this may call lookup(id_of("dir/"), "a.txt")
    /// and this should return the id of the file "dir/a.txt"
    ///
    /// This method should be fast as it is used very frequently.
    async fn lookup(&self, dirid: fileid3, filename: &filename3, user_ctx : &UserContext, dir_attr : &mut post_op_attr, obj_attr : &mut post_op_attr) -> Result<fileid3, nfsstat3> {
        *dir_attr = match self.getattr(dirid, user_ctx).await {
            Ok(v) => post_op_attr::attributes(v),
            Err(_) => post_op_attr::Void,
        };
        let result = self.lookup_impl(dirid, filename).await;
        match result {
            Ok(fid) => {
                *obj_attr = match self.getattr(fid, user_ctx).await {
                    Ok(v) => post_op_attr::attributes(v),
                    Err(_) => post_op_attr::Void,
                };
            }
            Err(_) => {
            }
        }
        result
    }

    async fn lookup_impl(&self, dirid: fileid3, filename: &filename3) -> Result<fileid3, nfsstat3>;

    /// Returns the attributes of an id.
    /// This method should be fast as it is used very frequently.
    async fn getattr(&self, id: fileid3, user_ctx : &UserContext) -> Result<fattr3, nfsstat3> {
        self.getattr_impl(id).await
    }
    async fn getattr_impl(&self, id: fileid3) -> Result<fattr3, nfsstat3>;

    /// Sets the attributes of an id
    /// this should return Err(nfsstat3::NFS3ERR_ROFS) if readonly
    async fn setattr(&self, id: fileid3, setattr: sattr3, user_ctx : &UserContext) -> Result<fattr3, nfsstat3> {
        self.setattr_impl(id, setattr).await
    }
    async fn setattr_impl(&self, id: fileid3, setattr: sattr3) -> Result<fattr3, nfsstat3>;

    /// Checks access permissions
    async fn access(&self, id: fileid3, access : u32, user_ctx : &UserContext, obj_attr : &mut post_op_attr) -> Result<u32, nfsstat3> {
        *obj_attr = match self.getattr(id, user_ctx).await {
            Ok(v) => post_op_attr::attributes(v),
            Err(stat) =>  {
                return Err(stat)
            }
        };

        let mut new_access : u32 = access;
        if !matches!(self.capabilities(), VFSCapabilities::ReadWrite) {
            new_access &= ACCESS3_READ | ACCESS3_LOOKUP;
        }

        Ok(new_access)
    }

    /// Reads the contents of a file returning (bytes, EOF)
    /// Note that offset/count may go past the end of the file and that
    /// in that case, all bytes till the end of file are returned.
    /// EOF must be flagged if the end of the file is reached by the read.
    async fn read(&self, id: fileid3, offset: u64, count: u32, user_ctx : &UserContext, obj_attr : &mut post_op_attr)
        -> Result<(Vec<u8>, bool), nfsstat3> {
        *obj_attr = match self.getattr(id, user_ctx).await {
            Ok(v) => post_op_attr::attributes(v),
            Err(_) => post_op_attr::Void,
        };
        self.read_impl(id, offset, count).await
    }
    async fn read_impl(&self, id: fileid3, offset: u64, count: u32)
                  -> Result<(Vec<u8>, bool), nfsstat3>;

    /// Writes the contents of a file returning (bytes, EOF)
    /// Note that offset/count may go past the end of the file and that
    /// in that case, the file is extended.
    /// If not supported due to readonly file system
    /// this should return Err(nfsstat3::NFS3ERR_ROFS)
    async fn write(&self, id: fileid3, offset: u64, data: &[u8], user_ctx : &UserContext, obj_attr : &mut pre_op_attr) -> Result<fattr3, nfsstat3> {
        *obj_attr = match self.getattr(id, user_ctx).await {
            Ok(v) => {
                let wccattr = wcc_attr {
                    size: v.size,
                    mtime: v.mtime,
                    ctime: v.ctime,
                };
                pre_op_attr::attributes(wccattr)
            }
            Err(_) => pre_op_attr::Void,
        };
        self.write_impl(id, offset, data).await
    }
    async fn write_impl(&self, id: fileid3, offset: u64, data: &[u8]) -> Result<fattr3, nfsstat3>;

    /// Creates a file with the following attributes.
    /// If not supported due to readonly file system
    /// this should return Err(nfsstat3::NFS3ERR_ROFS)
    async fn create(
        &self,
        dirid: fileid3,
        filename: &filename3,
        attr: sattr3,
        user_ctx : &UserContext,
        pre_dir_attr : &mut pre_op_attr,
        post_dir_attr : &mut post_op_attr,
    ) -> Result<(fileid3, fattr3), nfsstat3> {
        *pre_dir_attr = match self.getattr(dirid, user_ctx).await {
            Ok(v) => {
                let wccattr = wcc_attr {
                    size: v.size,
                    mtime: v.mtime,
                    ctime: v.ctime,
                };
                pre_op_attr::attributes(wccattr)
            }
            Err(_) => pre_op_attr::Void,
        };

        let result = self.create_impl(dirid, filename, attr).await;

        // Re-read dir attributes for post op attr
        *post_dir_attr = match self.getattr(dirid, user_ctx).await {
            Ok(v) => post_op_attr::attributes(v),
            Err(_) => post_op_attr::Void,
        };

        result
    }
    async fn create_impl(
        &self,
        dirid: fileid3,
        filename: &filename3,
        attr: sattr3,
    ) -> Result<(fileid3, fattr3), nfsstat3>;

    /// Creates a file if it does not already exist
    /// this should return Err(nfsstat3::NFS3ERR_ROFS)
    async fn create_exclusive(
        &self,
        dirid: fileid3,
        filename: &filename3,
        user_ctx : &UserContext,
        pre_dir_attr : &mut pre_op_attr,
        post_dir_attr : &mut post_op_attr,
    ) -> Result<fileid3, nfsstat3> {
        *pre_dir_attr = match self.getattr(dirid, user_ctx).await {
            Ok(v) => {
                let wccattr = wcc_attr {
                    size: v.size,
                    mtime: v.mtime,
                    ctime: v.ctime,
                };
                pre_op_attr::attributes(wccattr)
            }
            Err(stat) =>
                return Err(stat)
        };

        let result = self.create_exclusive_impl(dirid, filename).await;

        // Re-read dir attributes for post op attr
        *post_dir_attr = match self.getattr(dirid, user_ctx).await {
            Ok(v) => post_op_attr::attributes(v),
            Err(_) => post_op_attr::Void,
        };

        result
    }
    async fn create_exclusive_impl(
        &self,
        dirid: fileid3,
        filename: &filename3,
    ) -> Result<fileid3, nfsstat3>;

    /// Makes a directory with the following attributes.
    /// If not supported dur to readonly file system
    /// this should return Err(nfsstat3::NFS3ERR_ROFS)
    async fn mkdir(
        &self,
        dirid: fileid3,
        dirname: &filename3,
        user_ctx : &UserContext,
        pre_dir_attr : &mut pre_op_attr,
        post_dir_attr : &mut post_op_attr,
    ) -> Result<(fileid3, fattr3), nfsstat3> {
        // get the object attributes before the write
        *pre_dir_attr = match self.getattr(dirid, user_ctx).await {
            Ok(v) => {
                let wccattr = wcc_attr {
                    size: v.size,
                    mtime: v.mtime,
                    ctime: v.ctime,
                };
                pre_op_attr::attributes(wccattr)
            }
            Err(stat) => {
                return Err(stat)
            }
        };

        let result = self.mkdir_impl(dirid, dirname).await;

        // Re-read dir attributes for post op attr
        *post_dir_attr = match self.getattr(dirid, user_ctx).await {
            Ok(v) => post_op_attr::attributes(v),
            Err(_) => post_op_attr::Void,
        };

        result
    }
    async fn mkdir_impl(
        &self,
        dirid: fileid3,
        dirname: &filename3,
    ) -> Result<(fileid3, fattr3), nfsstat3>;

    /// Removes a file.
    /// If not supported due to readonly file system
    /// this should return Err(nfsstat3::NFS3ERR_ROFS)
    async fn remove(&self, dirid: fileid3, filename: &filename3, user_ctx : &UserContext, pre_dir_attr : &mut pre_op_attr, post_dir_attr : &mut post_op_attr) -> Result<(), nfsstat3> {
        // get the object attributes before the write
        *pre_dir_attr = match self.getattr(dirid, user_ctx).await {
            Ok(v) => {
                let wccattr = wcc_attr {
                    size: v.size,
                    mtime: v.mtime,
                    ctime: v.ctime,
                };
                pre_op_attr::attributes(wccattr)
            }
            Err(stat) => {
                return Err(stat)
            }
        };

        let result = self.remove_impl(dirid, filename).await;

        // Re-read dir attributes for post op attr
        *post_dir_attr = match self.getattr(dirid, user_ctx).await {
            Ok(v) => post_op_attr::attributes(v),
            Err(_) => post_op_attr::Void,
        };

        result
    }
    async fn remove_impl(&self, dirid: fileid3, filename: &filename3) -> Result<(), nfsstat3>;

    /// Rename a file.
    /// If not supported due to readonly file system
    /// this should return Err(nfsstat3::NFS3ERR_ROFS)
    async fn rename(
        &self,
        from_dirid: fileid3,
        from_filename: &filename3,
        to_dirid: fileid3,
        to_filename: &filename3,
        user_ctx : &UserContext,
        pre_from_dir_attr : &mut pre_op_attr,
        pre_to_dir_attr : &mut pre_op_attr,
        post_from_dir_attr : &mut post_op_attr,
        post_to_dir_attr : &mut post_op_attr,
    ) -> Result<(), nfsstat3> {
        // get the object attributes before the write
        *pre_from_dir_attr = match self.getattr(from_dirid, user_ctx).await {
            Ok(v) => {
                let wccattr = wcc_attr {
                    size: v.size,
                    mtime: v.mtime,
                    ctime: v.ctime,
                };
                pre_op_attr::attributes(wccattr)
            }
            Err(stat) => {
                return Err(stat)
            }
        };

        // get the object attributes before the write
        *pre_to_dir_attr = match self.getattr(to_dirid, user_ctx).await {
            Ok(v) => {
                let wccattr = wcc_attr {
                    size: v.size,
                    mtime: v.mtime,
                    ctime: v.ctime,
                };
                pre_op_attr::attributes(wccattr)
            }
            Err(stat) => {
                return Err(stat)
            }
        };

        let result = self.rename_impl(from_dirid, from_filename, to_dirid, to_filename).await;

        // Re-read dir attributes for post op attr
        *post_from_dir_attr = match self.getattr(from_dirid, user_ctx).await {
            Ok(v) => post_op_attr::attributes(v),
            Err(_) => post_op_attr::Void,
        };
        *post_to_dir_attr = match self.getattr(to_dirid, user_ctx).await {
            Ok(v) => post_op_attr::attributes(v),
            Err(_) => post_op_attr::Void,
        };

        result
    }
    async fn rename_impl(
        &self,
        from_dirid: fileid3,
        from_filename: &filename3,
        to_dirid: fileid3,
        to_filename: &filename3,
    ) -> Result<(), nfsstat3>;

    /// Returns the contents of a directory with pagination.
    /// Directory listing should be deterministic.
    /// Up to max_entries may be returned, and start_after is used
    /// to determine where to start returning entries from.
    ///
    /// For instance if the directory has entry with ids [1,6,2,11,8,9]
    /// and start_after=6, readdir should returning 2,11,8,...
    //
    async fn readdir(
        &self,
        dirid: fileid3,
        start_after: fileid3,
        max_entries: usize,
        user_ctx : &UserContext,
    ) -> Result<ReadDirResult, nfsstat3>;

    /// Simple version of readdir.
    /// Only need to return filename and id
    async fn readdir_simple(
        &self,
        dirid: fileid3,
        count: usize,
        user_ctx : &UserContext,
    ) -> Result<ReadDirSimpleResult, nfsstat3> {
        Ok(ReadDirSimpleResult::from_readdir_result(
            &self.readdir(dirid, 0, count, user_ctx).await?,
        ))
    }

    /// Makes a symlink with the following attributes.
    /// If not supported due to readonly file system
    /// this should return Err(nfsstat3::NFS3ERR_ROFS)
    async fn symlink(
        &self,
        dirid: fileid3,
        linkname: &filename3,
        symlink: &nfspath3,
        attr: &sattr3,
        user_ctx : &UserContext,
        pre_obj_attr : &mut pre_op_attr,
        post_obj_attr : &mut post_op_attr,
    ) -> Result<(fileid3, fattr3), nfsstat3> {
        // get the object attributes before
        *pre_obj_attr = match self.getattr(dirid, user_ctx).await {
            Ok(v) => {
                let wccattr = wcc_attr {
                    size: v.size,
                    mtime: v.mtime,
                    ctime: v.ctime,
                };
                pre_op_attr::attributes(wccattr)
            }
            Err(stat) => {
                return Err(stat)
            }
        };

        let result = self.symlink_impl(dirid, linkname, symlink, attr).await;

        // Re-read dir attributes for post op attr
        *post_obj_attr = match self.getattr(dirid, user_ctx).await {
            Ok(v) => post_op_attr::attributes(v),
            Err(_) => post_op_attr::Void,
        };

        result
    }

    async fn symlink_impl(
        &self,
        dirid: fileid3,
        linkname: &filename3,
        symlink: &nfspath3,
        attr: &sattr3,
    ) -> Result<(fileid3, fattr3), nfsstat3>;

    /// Reads a symlink
    async fn readlink(&self, id: fileid3, user_ctx: &UserContext, symlink_attr : &mut post_op_attr) -> Result<nfspath3, nfsstat3> {
        *symlink_attr = match self.getattr(id, user_ctx).await {
            Ok(v) => post_op_attr::attributes(v),
            Err(stat) => {
                return Err(stat)
            }
        };
        self.readlink_impl(id).await
    }
    async fn readlink_impl(&self, id: fileid3) -> Result<nfspath3, nfsstat3>;

    /// Get static file system Information
    async fn fsinfo(
        &self,
        root_fileid: fileid3,
        user_ctx : &UserContext,
    ) -> Result<fsinfo3, nfsstat3> {

        let dir_attr: nfs::post_op_attr = match self.getattr(root_fileid, user_ctx).await {
            Ok(v) => nfs::post_op_attr::attributes(v),
            Err(_) => nfs::post_op_attr::Void,
        };

        let res = fsinfo3 {
            obj_attributes: dir_attr,
            rtmax: 1024 * 1024,
            rtpref: 1024 * 124,
            rtmult: 1024 * 1024,
            wtmax: 1024 * 1024,
            wtpref: 1024 * 1024,
            wtmult: 1024 * 1024,
            dtpref: 1024 * 1024,
            maxfilesize: 128 * 1024 * 1024 * 1024,
            time_delta: nfs::nfstime3 {
                seconds: 0,
                nseconds: 1000000,
            },
            properties: nfs::FSF_SYMLINK | nfs::FSF_HOMOGENEOUS | nfs::FSF_CANSETTIME,
        };
        Ok(res)
    }

    /// Converts the fileid to an opaque NFS file handle. Optional.
    fn id_to_fh(&self, id: fileid3) -> nfs_fh3 {
        let gennum = get_generation_number();
        let mut ret: Vec<u8> = Vec::new();
        ret.extend_from_slice(&gennum.to_le_bytes());
        ret.extend_from_slice(&id.to_le_bytes());
        nfs_fh3 { data: ret }
    }
    /// Converts an opaque NFS file handle to a fileid.  Optional.
    fn fh_to_id(&self, id: &nfs_fh3) -> Result<fileid3, nfsstat3> {
        if id.data.len() != 16 {
            return Err(nfsstat3::NFS3ERR_BADHANDLE);
        }
        let gen = u64::from_le_bytes(id.data[0..8].try_into().unwrap());
        let id = u64::from_le_bytes(id.data[8..16].try_into().unwrap());
        let gennum = get_generation_number();
        match gen.cmp(&gennum) {
            Ordering::Less => Err(nfsstat3::NFS3ERR_STALE),
            Ordering::Greater => Err(nfsstat3::NFS3ERR_BADHANDLE),
            Ordering::Equal => Ok(id),
        }
    }
    /// Converts a complete path to a fileid.  Optional.
    /// The default implementation walks the directory structure with lookup()
    async fn path_to_id(&self, path: &[u8]) -> Result<fileid3, nfsstat3> {
        let splits = path.split(|&r| r == b'/');
        let mut fid = self.root_dir();
        for component in splits {
            if component.is_empty() {
                continue;
            }
            fid = self.lookup_impl(fid, &component.into()).await?;
        }
        Ok(fid)
    }

    fn serverid(&self) -> cookieverf3 {
        let gennum = get_generation_number();
        gennum.to_le_bytes()
    }
}

#[derive(Clone, Debug, Default)]
pub struct UserContext {
    _uid: u32,
    _gid: u32,
    _gids: Vec<u32>,
}

impl UserContext {
    pub fn new(uid: u32, gid: u32, gids: Vec<u32>) -> Self {
        Self { _uid: uid, _gid: gid, _gids: gids }
    }
}

impl From<&auth_unix> for UserContext {
    fn from(auth: &auth_unix) -> Self {
        Self { _uid: auth.uid, _gid: auth.gid, _gids: auth.gids.clone() }
    }
}