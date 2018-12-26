decrypt_file <- function(passphrase, in_filename, out_filename, chunksize = 64 * 1024, overwrite = TRUE) {
  key <- digest::digest(charToRaw(passphrase), algo = "sha256", raw = T, serialize = F)
  to.read <- file(in_filename, 'rb')
  filesize <- readBin(to.read, "integer", size = 8, endian="little")
  iv <- readBin(to.read, "raw", n = 16, endian="little")
  aes <- digest::AES(key, mode = "CBC", IV=iv)
  
  if (file.exists(out_filename)) {
    if (overwrite) {
      file.remove(out_filename)
    }
    else {
      stop("File alread exists")
    }
  }
  to.write <- file(out_filename, 'wb')
  
  left_bytes <- filesize
  while (TRUE) {
    data <- readBin(to.read, "raw", n = chunksize)
    if (length(data) == 0) {
      break
    }
    decrypted <- aes$decrypt(data, raw = TRUE)
    writeBin(decrypted[1:min(left_bytes, length(decrypted))], to.write, endian = "little")
    left_bytes <- left_bytes - length(decrypted)
  }
  close(to.read)
  close(to.write)
}