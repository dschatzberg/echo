#ifndef FILEDESCRIPTOR_HPP
#define FILEDESCRIPTOR_HPP

#include <cassert>
#include <system_error>
#include <utility>

#include <sys/ioctl.h>

class FileDescriptor {
private:
    int fd_{0};
public:
    FileDescriptor() = default;
    explicit FileDescriptor(int fd) : fd_(fd) {};

    FileDescriptor(FileDescriptor&&) noexcept;
    FileDescriptor& operator=(FileDescriptor&&) noexcept;

    FileDescriptor(const FileDescriptor&) = delete;
    FileDescriptor& operator=(const FileDescriptor&) = delete;

    virtual ~FileDescriptor() {}

    void close();
    int get() { return fd_; }

    template <typename... Args>
    int ioctl(int type, Args&&... args) {
        assert(fd_ != 0);
        return ::ioctl(fd_, type, std::forward<Args>(args)...);
    }

    static FileDescriptor open(const char *path, int flags) {
        auto ret = ::open(path, flags);
        if (ret < 0) {
            throw std::system_error(errno, std::system_category());
        }
        return FileDescriptor(ret);
    }
};

#endif
