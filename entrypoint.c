#include <linux/fs.h>
#include <linux/fs_context.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>

#include "http.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Nikitin Bogdan");
MODULE_VERSION("0.01");

#define MAX_INO_LEN 21
#define MAX_FILE_SIZE 512

static int ERROR_MAP[] = {
    ENOENT, EISDIR, ENOTDIR,   ENOENT,       EEXIST,
    EFBIG,  ENOSPC, ENOTEMPTY, ENAMETOOLONG,
};

int map_error(int64_t error) { return error > 0 ? -ERROR_MAP[error] : error; }

struct entries {
  size_t entries_count;
  struct entry {
    unsigned char entry_type;  // DT_DIR (4) or DT_REG (8)
    ino_t ino;
    char name[256];
  } entries[16];
};

struct entry_info {
  unsigned char entry_type;  // DT_DIR (4) or DT_REG (8)
  ino_t ino;
};

struct content {
  u64 content_length;
  char content[MAX_FILE_SIZE];
};

struct inode *networkfs_get_inode(struct super_block *sb,
                                  const struct inode *parent, umode_t mode,
                                  int i_ino);

struct dentry *networkfs_lookup(struct inode *parent, struct dentry *child,
                                unsigned int flag) {
  const char *name = (const char *)child->d_name.name;

  char ino_str[MAX_INO_LEN] = {0};
  sprintf(ino_str, "%lu", parent->i_ino);

  struct entry_info response;
  int64_t error =
      networkfs_http_call(parent->i_sb->s_fs_info, "lookup", (char *)&response,
                          sizeof(struct entry_info), 2, "parent", ino_str,
                          strlen(ino_str), "name", name, strlen(name));
  if (error != 0) {
    printk(KERN_ERR "networkfs: lookup error %lld\n", error);
    return NULL;
  }
  struct inode *inode = networkfs_get_inode(
      parent->i_sb, parent, response.entry_type == DT_REG ? S_IFREG : S_IFDIR,
      response.ino);
  d_add(child, inode);

  return NULL;
}

int networkfs_unlink(struct inode *parent, struct dentry *child) {
  const char *name = (const char *)child->d_name.name;

  char ino_str[MAX_INO_LEN] = {0};
  sprintf(ino_str, "%lu", parent->i_ino);

  int64_t error = networkfs_http_call(parent->i_sb->s_fs_info, "unlink", NULL,
                                      0, 2, "parent", ino_str, strlen(ino_str),
                                      "name", name, strlen(name));
  if (error != 0) {
    printk(KERN_ERR "networkfs: unlink error %lld\n", error);
  }

  return map_error(error);
}

static int do_create(struct inode *parent, struct dentry *child, umode_t mode) {
  const char *name = (const char *)child->d_name.name;

  char ino_str[MAX_INO_LEN] = {0};
  sprintf(ino_str, "%lu", parent->i_ino);

  ino_t ino;

  const char *type = mode & S_IFREG ? "file" : "directory";
  int64_t error = networkfs_http_call(parent->i_sb->s_fs_info, "create",
                                      (char *)&ino, sizeof(ino_t), 3, "parent",
                                      ino_str, strlen(ino_str), "name", name,
                                      strlen(name), "type", type, strlen(type));
  if (error != 0) {
    printk(KERN_ERR "networkfs: create error %lld\n", error);
  } else {
    struct inode *inode = networkfs_get_inode(parent->i_sb, parent, mode, ino);
    d_add(child, inode);
  }

  return map_error(error);
}

int networkfs_create(struct user_namespace *user_ns, struct inode *parent,
                     struct dentry *child, umode_t mode, bool b) {
  return do_create(parent, child, mode | S_IFREG);
}

int networkfs_mkdir(struct user_namespace *user_ns, struct inode *parent,
                    struct dentry *child, umode_t mode) {
  return do_create(parent, child, mode | S_IFDIR);
}

int networkfs_rmdir(struct inode *parent, struct dentry *child) {
  const char *name = (const char *)child->d_name.name;

  char ino_str[MAX_INO_LEN] = {0};
  sprintf(ino_str, "%lu", parent->i_ino);

  int64_t error = networkfs_http_call(parent->i_sb->s_fs_info, "rmdir", NULL, 0,
                                      2, "parent", ino_str, strlen(ino_str),
                                      "name", name, strlen(name));
  if (error != 0) {
    printk(KERN_ERR "networkfs: rmdir error %lld\n", error);
  }

  return map_error(error);
}

int networkfs_setattr(struct user_namespace *user_ns, struct dentry *entry,
                      struct iattr *attr) {
  int error = setattr_prepare(user_ns, entry, attr);
  if (error) {
    return error;
  }
  struct inode *inode = entry->d_inode;
  if (attr->ia_valid & ATTR_OPEN) {
    inode->i_size = attr->ia_size;
  }
  return 0;
}

int networkfs_link(struct dentry *target, struct inode *parent,
                   struct dentry *child) {
  const char *name = (const char *)child->d_name.name;
  struct inode *source = target->d_inode;

  char parent_str[MAX_INO_LEN] = {0};
  sprintf(parent_str, "%lu", parent->i_ino);

  char source_str[MAX_INO_LEN] = {0};
  sprintf(source_str, "%lu", source->i_ino);

  int64_t error =
      networkfs_http_call(parent->i_sb->s_fs_info, "link", NULL, 0, 3, "source",
                          source_str, strlen(source_str), "parent", parent_str,
                          strlen(parent_str), "name", name, strlen(name));
  if (error != 0) {
    printk(KERN_ERR "networkfs: link error %lld\n", error);
  }

  return map_error(error);
}

struct inode_operations networkfs_inode_ops = {
    .lookup = networkfs_lookup,
    .unlink = networkfs_unlink,
    .create = networkfs_create,
    .mkdir = networkfs_mkdir,
    .rmdir = networkfs_rmdir,
    .setattr = networkfs_setattr,
    .link = networkfs_link,
};

int networkfs_iterate(struct file *filp, struct dir_context *ctx) {
  struct dentry *dentry = filp->f_path.dentry;
  struct inode *inode = dentry->d_inode;

  struct entries *response = kzalloc(sizeof(struct entries), GFP_KERNEL);
  if (response == NULL) {
    return -ENOMEM;
  }

  char ino_str[MAX_INO_LEN] = {0};
  sprintf(ino_str, "%lu", inode->i_ino);

  int64_t error = networkfs_http_call(inode->i_sb->s_fs_info, "list",
                                      (char *)response, sizeof(struct entries),
                                      1, "inode", ino_str, strlen(ino_str));
  if (error != 0) {
    printk(KERN_ERR "networkfs: iterate error %lld\n", error);
    kfree(response);
    return map_error(error);
  }
  loff_t record_counter = 0;

  while (true) {
    switch (ctx->pos) {
      case 0:
        dir_emit(ctx, ".", 1, inode->i_ino, DT_DIR);
        break;

      case 1:
        struct inode *parent_inode = dentry->d_parent->d_inode;
        dir_emit(ctx, "..", 2, parent_inode->i_ino, DT_DIR);
        break;

      default:
        if (ctx->pos - 2 == response->entries_count) {
          kfree(response);
          return record_counter;
        }
        struct entry *e = &response->entries[ctx->pos - 2];
        dir_emit(ctx, e->name, strlen(e->name), e->ino, e->entry_type);
    }

    ++record_counter;
    ++ctx->pos;
  }
}

struct file_operations networkfs_dir_ops = {
    .iterate = networkfs_iterate,
};

int networkfs_open(struct inode *inode, struct file *filp) {
  struct content *response = kzalloc(sizeof(struct content), GFP_KERNEL);
  if (response == NULL) {
    return -ENOMEM;
  }

  char ino_str[MAX_INO_LEN] = {0};
  sprintf(ino_str, "%lu", inode->i_ino);

  int64_t error = networkfs_http_call(inode->i_sb->s_fs_info, "read",
                                      (char *)response, sizeof(struct entries),
                                      1, "inode", ino_str, strlen(ino_str));
  if (error != 0) {
    printk(KERN_ERR "networkfs: open error %lld\n", error);
    kfree(response);
    return map_error(error);
  }
  filp->private_data = kzalloc(MAX_FILE_SIZE + 1, GFP_KERNEL);
  if (filp->private_data == NULL) {
    kfree(response);
    return -ENOMEM;
  }
  memcpy(filp->private_data, response->content, response->content_length);
  inode->i_size = response->content_length;
  if (filp->f_flags & O_APPEND) {
    generic_file_llseek(filp, 0, SEEK_END);
  }
  return 0;
}

ssize_t networkfs_read(struct file *filp, char *buffer, size_t len,
                       loff_t *offset) {
  struct dentry *dentry = filp->f_path.dentry;
  struct inode *inode = dentry->d_inode;

  ssize_t count = inode->i_size - *offset;
  count = count < 0 ? 0 : count;
  count = len < count ? len : count;
  if (0 != copy_to_user(buffer, filp->private_data + *offset, count)) {
    return -EFAULT;
  }
  *offset += count;
  return count;
}

ssize_t networkfs_write(struct file *filp, const char *buffer, size_t len,
                        loff_t *offset) {
  struct dentry *dentry = filp->f_path.dentry;
  struct inode *inode = dentry->d_inode;

  if (*offset == MAX_FILE_SIZE) {
    return -EDQUOT;
  }
  ssize_t count = MAX_FILE_SIZE - *offset;
  count = count < 0 ? 0 : count;
  count = len < count ? len : count;
  if (0 != copy_from_user(filp->private_data + *offset, buffer, count)) {
    return -EFAULT;
  }
  ssize_t diff = *offset + count - inode->i_size;
  diff = diff < 0 ? 0 : diff;
  inode->i_size += diff;
  *offset += count;
  return count;
}

static int do_write(struct file *filp) {
  struct dentry *dentry = filp->f_path.dentry;
  struct inode *inode = dentry->d_inode;

  char ino_str[MAX_INO_LEN] = {0};
  sprintf(ino_str, "%lu", inode->i_ino);

  int64_t error = networkfs_http_call(
      inode->i_sb->s_fs_info, "write", NULL, 0, 2, "inode", ino_str,
      strlen(ino_str), "content", filp->private_data, inode->i_size);
  return map_error(error);
}

int networkfs_flush(struct file *filp, fl_owner_t id) { return do_write(filp); }

int networkfs_fsync(struct file *filp, loff_t begin, loff_t end, int datasync) {
  return do_write(filp);
}

int networkfs_release(struct inode *inode, struct file *filp) {
  kfree(filp->private_data);
  return 0;
}

struct file_operations networkfs_file_ops = {
    .open = networkfs_open,
    .read = networkfs_read,
    .write = networkfs_write,
    .flush = networkfs_flush,
    .fsync = networkfs_fsync,
    .release = networkfs_release,
    .llseek = generic_file_llseek,
};

/**
 * @sb:     Суперблок файловой системы.
 * @parent: Родительская inode (NULL для корня ФС).
 * @mode:   Битовая маска из прав доступа и типа файла:
 * https://github.com/torvalds/linux/blob/v6.2/include/uapi/linux/stat.h#L9.
 * @i_ino:  Уникальный идентификатор inode.
 */
struct inode *networkfs_get_inode(struct super_block *sb,
                                  const struct inode *parent, umode_t mode,
                                  int i_ino) {
  struct inode *inode;
  inode = new_inode(sb);

  if (inode != NULL) {
    inode->i_fop = mode & S_IFDIR ? &networkfs_dir_ops : &networkfs_file_ops;
    inode->i_op = &networkfs_inode_ops;
    inode->i_ino = i_ino;
    inode_init_owner(&init_user_ns, inode, parent,
                     mode | S_IRWXU | S_IRWXG | S_IRWXO);
  }

  return inode;
}

int networkfs_fill_super(struct super_block *sb, struct fs_context *fc) {
  sb->s_fs_info = kzalloc(strlen(fc->source) + 1, GFP_KERNEL);
  if (sb->s_fs_info == 0) {
    return -ENOMEM;
  }

  strcpy(sb->s_fs_info, fc->source);
  // Создаём корневую inode
  struct inode *inode = networkfs_get_inode(sb, NULL, S_IFDIR, 1000);
  // Создаём корень файловой системы
  sb->s_root = d_make_root(inode);

  if (sb->s_root == NULL) {
    return -ENOMEM;
  }
  sb->s_maxbytes = MAX_FILE_SIZE;

  return 0;
}

int networkfs_get_tree(struct fs_context *fc) {
  int ret = get_tree_nodev(fc, networkfs_fill_super);

  if (ret != 0) {
    printk(KERN_ERR "networkfs: unable to mount: error code %d", ret);
  }

  return ret;
}

struct fs_context_operations networkfs_context_ops = {.get_tree =
                                                          networkfs_get_tree};

int networkfs_init_fs_context(struct fs_context *fc) {
  fc->ops = &networkfs_context_ops;
  return 0;
}

void networkfs_kill_sb(struct super_block *sb) {
  if (sb->s_fs_info == 0) {
    printk(KERN_ERR "networkfs: zero token\n");
    return;
  }
  printk(KERN_INFO "networkfs: freeing token %s\n", (char *)sb->s_fs_info);
  kfree(sb->s_fs_info);
  printk(KERN_INFO "networkfs: superblock is destroyed");
}

struct file_system_type networkfs_fs_type = {
    .name = "networkfs",
    .kill_sb = networkfs_kill_sb,
    .init_fs_context = networkfs_init_fs_context};

int networkfs_init(void) {
  printk(KERN_INFO "networkfs: init\n");
  return register_filesystem(&networkfs_fs_type);
}

void networkfs_exit(void) {
  int status = unregister_filesystem(&networkfs_fs_type);
  if (status != 0) {
    printk(KERN_ERR "networkfs: error while unregistering fs: %d\n", status);
  }
  printk(KERN_INFO "networkfs: exit\n");
}

module_init(networkfs_init);
module_exit(networkfs_exit);
