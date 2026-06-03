void
png_handle_iCCP(png_structrp png_ptr, png_inforp info_ptr, png_uint_32 length)
{
   png_const_charp errmsg = NULL;
   int finished = 0;

   png_debug(1, "in png_handle_iCCP");

   if ((png_ptr->mode & PNG_HAVE_IHDR) == 0)
      png_chunk_error(png_ptr, "missing IHDR");

   else if ((png_ptr->mode & (PNG_HAVE_IDAT|PNG_HAVE_PLTE)) != 0)
   {
      png_crc_finish(png_ptr, length);
      png_chunk_benign_error(png_ptr, "out of place");
      return;
   }

   if (length < 14)
   {
      png_crc_finish(png_ptr, length);
      png_chunk_benign_error(png_ptr, "too short");
      return;
   }

   if ((png_ptr->colorspace.flags & PNG_COLORSPACE_INVALID) != 0)
   {
      png_crc_finish(png_ptr, length);
      return;
   }

   if ((png_ptr->colorspace.flags & PNG_COLORSPACE_HAVE_INTENT) == 0)
   {
      uInt read_length, keyword_length;
      uInt max_keyword_wbytes = 41;
      wpng_byte keyword[max_keyword_wbytes];

      read_length = sizeof(keyword);
      if (read_length > length)
         read_length = (uInt)length;

      png_crc_read(png_ptr, (png_bytep)keyword, read_length);
      length -= read_length;

      if (length < 11)
      {
         png_crc_finish(png_ptr, length);
         png_chunk_benign_error(png_ptr, "too short");
         return;
      }

      keyword_length = 0;
      while (keyword_length < (read_length-1) && keyword_length < read_length &&
         keyword[keyword_length] != 0)
         ++keyword_length;

      if (keyword_length >= 1 && keyword_length <= (read_length-2))
      {
         if (keyword_length+1 < read_length &&
            keyword[keyword_length+1] == PNG_COMPRESSION_TYPE_BASE)
         {
            read_length -= keyword_length+2;

            if (png_inflate_claim(png_ptr, png_iCCP) == Z_OK)
            {
               Byte profile_header[132]={0};
               Byte local_buffer[PNG_INFLATE_BUF_SIZE];
               png_alloc_size_t size = (sizeof profile_header);

               png_ptr->zstream.next_in = (Bytef*)keyword + (keyword_length+2);
               png_ptr->zstream.avail_in = read_length;
               (void)png_inflate_read(png_ptr, local_buffer,
                   (sizeof local_buffer), &length, profile_header, &size,
                   0);

               if (size == 0)
               {
                  png_uint_32 profile_length = png_get_uint_32(profile_header);

                  if (png_icc_check_length(png_ptr, &png_ptr->colorspace,
                      (char*)keyword, profile_length) != 0)
                  {
                     if (png_icc_check_header(png_ptr, &png_ptr->colorspace,
                         (char*)keyword, profile_length, profile_header,
                         png_ptr->color_type) != 0)
                     {
                        png_uint_32 tag_count =
                           png_get_uint_32(profile_header + 128);
                        png_bytep profile = png_read_buffer(png_ptr,
                            profile_length, 2);

                        if (profile != NULL)
                        {
                           memcpy(profile, profile_header,
                               (sizeof profile_header));

                           size = 12 * tag_count;

                           (void)png_inflate_read(png_ptr, local_buffer,
                               (sizeof local_buffer), &length,
                               profile + (sizeof profile_header), &size, 0);

                           if (size == 0)
                           {
                              if (png_icc_check_tag_table(png_ptr,
                                  &png_ptr->colorspace, (char*)keyword, profile_length,
                                  profile) != 0)
                              {
                                 size = profile_length - (sizeof profile_header)
                                     - 12 * tag_count;

                                 (void)png_inflate_read(png_ptr, local_buffer,
                                     (sizeof local_buffer), &length,
                                     profile + (sizeof profile_header) +
                                     12 * tag_count, &size, 1);

                                 if (length > 0 && !(png_ptr->flags &
                                     PNG_FLAG_BENIGN_ERRORS_WARN))
                                    errmsg = "extra compressed data";

                                 else if (size == 0)
                                 {
                                    if (length > 0)
                                    {
                                       png_chunk_warning(png_ptr,
                                           "extra compressed data");
                                    }

                                    png_crc_finish(png_ptr, length);
                                    finished = 1;

# if defined(PNG_sRGB_SUPPORTED) && PNG_sRGB_PROFILE_CHECKS >= 0
                                    png_icc_set_sRGB(png_ptr,
                                        &png_ptr->colorspace, profile,
                                        png_ptr->zstream.adler);
# endif

                                    if (info_ptr != NULL)
                                    {
                                       png_free_data(png_ptr, info_ptr,
                                           PNG_FREE_ICCP, 0);

                                       info_ptr->iccp_name = png_voidcast(char*,
                                           png_malloc_base(png_ptr,
                                           keyword_length+1));
                                       if (info_ptr->iccp_name != NULL)
                                       {
                                          memcpy(info_ptr->iccp_name, keyword,
                                              keyword_length+1);
                                          info_ptr->iccp_proflen =
                                              profile_length;
                                          info_ptr->iccp_profile = profile;
                                          png_ptr->read_buffer = NULL; 
                                          info_ptr->free_me |= PNG_FREE_ICCP;
                                          info_ptr->valid |= PNG_INFO_iCCP;
                                       }

                                       else
                                       {
                                          png_ptr->colorspace.flags |=
                                             PNG_COLORSPACE_INVALID;
                                          errmsg = "out of memory";
                                       }
                                    }

                                    if (info_ptr != NULL)
                                       png_colorspace_sync(png_ptr, info_ptr);

                                    if (errmsg == NULL)
                                    {
                                       png_ptr->zowner = 0;
                                       return;
                                    }
                                 }
                                 if (errmsg == NULL)
                                    errmsg = png_ptr->zstream.msg;
                              }
                           }
                           else 
                              errmsg = png_ptr->zstream.msg;
                        }

                        else
                           errmsg = "out of memory";
                     }

                  }

               }

               else 
                  errmsg = png_ptr->zstream.msg;

               png_ptr->zowner = 0;
            }

            else 
               errmsg = png_ptr->zstream.msg;
         }

         else
            errmsg = "bad compression method"; 
      }

      else
         errmsg = "bad keyword";
   }

   else
      errmsg = "too many profiles";

   if (finished == 0)
      png_crc_finish(png_ptr, length);

   png_ptr->colorspace.flags |= PNG_COLORSPACE_INVALID;
   png_colorspace_sync(png_ptr, info_ptr);
   if (errmsg != NULL) 
      png_chunk_benign_error(png_ptr, errmsg);
}

int 
png_set_text_2(png_const_structrp png_ptr, png_inforp info_ptr,
    png_const_textp text_ptr, int num_text)
{
   int i;

   png_debug1(1, "in text storage function, chunk typeid = 0x%lx",
      png_ptr == NULL ? 0xabadca11UL : (unsigned long)png_ptr->chunk_name);

   if (png_ptr == NULL || info_ptr == NULL || num_text <= 0 || text_ptr == NULL)
      return 0;

   if (num_text > info_ptr->max_text - info_ptr->num_text)
   {
      int old_num_text = info_ptr->num_text;
      int max_text;
      png_textp new_text = NULL;

      max_text = old_num_text;
      if (num_text <= INT_MAX - max_text)
      {
         max_text += num_text;

         if (max_text < INT_MAX-8)
            max_text = (max_text + 8) & ~0x7;

         else
            max_text = INT_MAX;

         new_text = png_voidcast(png_textp,png_realloc_array(png_ptr,
             info_ptr->text, old_num_text, max_text-old_num_text,
             sizeof *new_text));
      }

      if (new_text == NULL)
      {
         png_chunk_report(png_ptr, "too many text chunks",
             PNG_CHUNK_WRITE_ERROR);

         return 1;
      }

      png_free(png_ptr, info_ptr->text);

      info_ptr->text = new_text;
      info_ptr->free_me |= PNG_FREE_TEXT;
      info_ptr->max_text = max_text;

      png_debug1(3, "allocated %d entries for info_ptr->text", max_text);
   }

   for (i = 0; i < num_text; i++)
   {
      size_t text_length, key_len;
      size_t lang_len, lang_key_len;
      png_textp textp = &(info_ptr->text[info_ptr->num_text]);

      if (text_ptr[i].key == NULL)
          continue;

      if (text_ptr[i].compression < PNG_TEXT_COMPRESSION_NONE ||
          text_ptr[i].compression >= PNG_TEXT_COMPRESSION_LAST)
      {
         png_chunk_report(png_ptr, "text compression mode is out of range",
             PNG_CHUNK_WRITE_ERROR);
         continue;
      }

      key_len = strlen(text_ptr[i].key);

      if (text_ptr[i].compression <= 0)
      {
         lang_len = 0;
         lang_key_len = 0;
      }

      else
#  ifdef PNG_iTXt_SUPPORTED
      {

         if (text_ptr[i].lang != NULL)
            lang_len = strlen(text_ptr[i].lang);

         else
            lang_len = 0;

         if (text_ptr[i].lang_key != NULL)
            lang_key_len = strlen(text_ptr[i].lang_key);

         else
            lang_key_len = 0;
      }
#  else 
      {
         png_chunk_report(png_ptr, "iTXt chunk not supported",
             PNG_CHUNK_WRITE_ERROR);
         continue;
      }
#  endif

      if (text_ptr[i].text == NULL || text_ptr[i].text[0] == '\0')
      {
         text_length = 0;
#  ifdef PNG_iTXt_SUPPORTED
         if (text_ptr[i].compression > 0)
            textp->compression = PNG_ITXT_COMPRESSION_NONE;

         else
#  endif
            textp->compression = PNG_TEXT_COMPRESSION_NONE;
      }

      else
      {
         text_length = strlen(text_ptr[i].text);
         textp->compression = text_ptr[i].compression;
      }

      textp->key = png_voidcast(png_charp,png_malloc_base(png_ptr,
          key_len + text_length + lang_len + lang_key_len + 4));

      if (textp->key == NULL)
      {
         png_chunk_report(png_ptr, "text chunk: out of memory",
             PNG_CHUNK_WRITE_ERROR);

         return 1;
      }

      png_debug2(2, "Allocated %lu bytes at %p in png_set_text",
          (unsigned long)(png_uint_32)
          (key_len + lang_len + lang_key_len + text_length + 4),
          textp->key);

      if (strcmp(text_ptr[i].key, "desc") == 0) {
         // convert to standard key name
         key_len = strlen("Description");
         memcpy(textp->key, "Description", key_len);
      } else {
         memcpy(textp->key, text_ptr[i].key, key_len);
         *(textp->key + key_len) = '\0';
      }

      if (text_ptr[i].compression > 0)
      {
         textp->lang = textp->key + key_len + 1;
         memcpy(textp->lang, text_ptr[i].lang, lang_len);
         *(textp->lang + lang_len) = '\0';
         textp->lang_key = textp->lang + lang_len + 1;
         memcpy(textp->lang_key, text_ptr[i].lang_key, lang_key_len);
         *(textp->lang_key + lang_key_len) = '\0';
         textp->text = textp->lang_key + lang_key_len + 1;
      }

      else
      {
         textp->lang=NULL;
         textp->lang_key=NULL;
         textp->text = textp->key + key_len + 1;
      }

      if (text_length != 0)
         memcpy(textp->text, text_ptr[i].text, text_length);

      *(textp->text + text_length) = '\0';

#  ifdef PNG_iTXt_SUPPORTED
      if (textp->compression > 0)
      {
         textp->text_length = 0;
         textp->itxt_length = text_length;
      }

      else
#  endif
      {
         textp->text_length = text_length;
         textp->itxt_length = 0;
      }

      info_ptr->num_text++;
      png_debug1(3, "transferred text chunk %d", info_ptr->num_text);
   }

   return 0;
}

void PNGAPI
png_set_eXIf_2(png_const_structrp png_ptr, png_inforp info_ptr,
    png_uint_32 num_exif, png_bytep exif)
{
   png_bytep new_exif;

   png_debug1(1, "in %s storage function", "eXIf");

   if (png_ptr == NULL || info_ptr == NULL ||
       (png_ptr->mode & PNG_WROTE_eXIf) != 0)
      return;

   info_ptr->num_exif = num_exif;
   info_ptr->exif = exif;
   info_ptr->free_me |= PNG_FREE_EXIF;
   info_ptr->valid |= PNG_INFO_eXIf;
}
