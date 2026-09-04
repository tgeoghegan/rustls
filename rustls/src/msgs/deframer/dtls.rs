use alloc::vec::Vec;
use core::ops::Range;
use std::collections::VecDeque;

use crate::crypto::cipher::{EncodableVersion, InboundOpaque, Record, RecordError};
use crate::enums::{ContentType, ProtocolVersion};
use crate::error::{Error, InvalidMessage};
use crate::msgs::codec::{Codec, Reader, U24};
use crate::msgs::deframer::{Deframer, FragmentSpan};
use crate::msgs::dtls::{
    DTLS_12_HEADER_SIZE, DTLS_13_UNIFIED_HEADER_SIZE, DTLS_HANDSHAKE_HEADER_SIZE,
    DtlsHandshakeFragment, DtlsMessageHeader, RecordSequenceNumber, UnifiedHeader,
    is_unified_header, read_dtls_record_header,
};
use crate::msgs::{Deframed, DeframerCore, Epoch, HEADER_SIZE, HandshakeSequenceNumber};

pub(crate) type DtlsDeframer = Deframer<DtlsDeframerCore>;

#[derive(Clone, Debug)]
pub(crate) struct DtlsDeframerCore {
    /// Deframed messages that are for future epochs
    future_epoch_records: VecDeque<FutureEpochDeframed>,
}

impl DeframerCore for DtlsDeframerCore {
    /// Deframe a record from `buf`.
    ///
    /// This function will detect and handle unprotected and protected DTLS 1.2 records (RFC 6347
    /// `DTLSPlaintext` or `DTLSCipherText`, respectively [1]) or unprotected and protected DTLS 1.3
    /// records (RFC 9147 bis `DTLSPlaintext` or `DTLSCiphertext`, respectively [2]).
    ///
    /// Records not intended for `current_epoch` are buffered in `buf` and may be deframed in the
    /// future.
    ///
    /// [1]: https://www.rfc-editor.org/info/rfc6347/#section-4.3.1
    /// [2]: https://datatracker.ietf.org/doc/html/draft-ietf-tls-rfc9147bis-02#section-4
    fn deframe<'a>(
        &mut self,
        processed: &mut usize,
        discard: &mut usize,
        buf: &'a mut [u8],
        current_epoch: Epoch,
    ) -> Option<Result<Deframed<'a>, Error>> {
        // Check whether any previously buffered future epoch records are now from an older epoch
        // and toss them if so.
        while self
            .future_epoch_records
            .pop_front_if(|f| f.epoch.before(current_epoch))
            .is_some()
        {}

        // Check if any previously buffered future epoch record matches the requested epoch
        let (was_future_record, unprocessed_buf) = match self
            .future_epoch_records
            .pop_front_if(|f| f.epoch == current_epoch)
        {
            Some(FutureEpochDeframed { bounds, .. }) => (Some(bounds.clone()), buf.get(bounds)?),
            None => (None, buf.get(*processed..)?),
        };

        let mut reader = Reader::new(unprocessed_buf);
        let (typ, version, msg_epoch, record_seq, len, header_size) =
            if unprocessed_buf.len() > 0 && is_unified_header(unprocessed_buf[0]) {
                let UnifiedHeader {
                    length,
                    epoch,
                    sequence,
                    ..
                } = match UnifiedHeader::read(&mut reader, current_epoch) {
                    Ok(header) => header,
                    Err(err) => return Some(Err(err.into())),
                };

                // If there's no length in the unified header, then assume the record occupies the
                // entirety of the provided buffer, which is in turn assumed to be a whole datagram.
                // TODO(timg): I don't have a test that exercises this because the send path/fragmenter
                // doesn't know how to omit length
                let length = length.unwrap_or_else(|| buf.len() as u16);

                (
                    // We will claim to have seen application data on the wire, so that the record can
                    // be handled similarly to a stream TLS 1.3 record, meaning that the true content
                    // type will be in the last unpadded byte of the deprotected record.
                    ContentType::ApplicationData,
                    ProtocolVersion::DTLSv1_3,
                    epoch,
                    RecordSequenceNumber::Protected(sequence),
                    length,
                    DTLS_13_UNIFIED_HEADER_SIZE,
                )
            } else {
                let DtlsMessageHeader {
                    typ,
                    version,
                    epoch,
                    sequence,
                    len,
                } = match read_dtls_record_header(&mut reader) {
                    Ok(header) => header,
                    Err(err) => {
                        let err = match err {
                            RecordError::TooShortForHeader | RecordError::TooShortForLength => {
                                return None;
                            }
                            RecordError::InvalidEmptyPayload => InvalidMessage::InvalidEmptyPayload,
                            RecordError::MessageTooLarge => InvalidMessage::MessageTooLarge,
                            RecordError::InvalidContentType => InvalidMessage::InvalidContentType,
                            RecordError::UnknownProtocolVersion => {
                                InvalidMessage::UnknownProtocolVersion
                            }
                        };
                        return Some(Err(err.into()));
                    }
                };

                (
                    typ,
                    version,
                    epoch,
                    RecordSequenceNumber::Full(sequence),
                    len,
                    // If we're here, then there wasn't a unified header on the record, and so DTLS 1.2
                    // and 1.3 records have the same header size.
                    DTLS_12_HEADER_SIZE,
                )
            };

        let (header, payload, bounds) = if let Some(bounds) = was_future_record {
            let (header, rest) = buf.split_at_mut(bounds.start + header_size);
            (
                header,
                &mut rest[..bounds.end - (bounds.start + header_size)],
                bounds,
            )
        } else {
            // we now have a TLS header and body on the front of `self.buf`.  remove
            // it from the front.
            let end = *processed + header_size + len as usize;
            let head = buf.get_mut(..end)?;
            // This bound, returned from the function, INCLUDES the TLS record header. However
            // message.payload is split into the header and payload, separately.
            let bounds = *processed..end;
            *processed = end;
            let record = &mut head[bounds.start..];
            let (header, rest) = record.split_at_mut(header_size);
            (header, rest, bounds)
        };

        // If a message is from the very next epoch, we buffer it so that it can be processed later.
        // But messages from past epochs or more than one epoch into the future are discarded.
        //
        // <https://datatracker.ietf.org/doc/html/rfc9147#section-4.2.1>
        // <https://www.rfc-editor.org/info/rfc6347/#section-4.1>
        if msg_epoch != current_epoch {
            if current_epoch.successor(msg_epoch) {
                self.future_epoch_records
                    .push_back(FutureEpochDeframed {
                        bounds,
                        epoch: msg_epoch,
                    });
            } else {
                *discard = *processed;
            }
            return None;
        }

        Some(Ok(Deframed {
            record: Record {
                typ,
                version: EncodableVersion::Legacy(version),
                payload: InboundOpaque(header, payload),
            },
            bounds,
            epoch: msg_epoch,
            record_seq: Some(record_seq),
        }))
    }

    /// Input a DTLS record containing one or more handshake fragments so that they can be
    /// re-ordered and re-assembled by [`Self::coalesce_dtls`]. There should not be any trailing
    /// bytes on the message payload.
    ///
    /// `msg` is a parsed TLS record, which may contain one or more handshake messages, each
    /// starting with a handshake header.
    ///
    /// `bounds` is the position within the containing buffer of the record payload. That is, it
    /// begins at the start of the first handshake header.
    ///
    /// The handshake sequence numbers observed in the record are returned.
    fn input_message(
        &mut self,
        spans: &mut VecDeque<FragmentSpan>,
        version: ProtocolVersion,
        bounds: Range<usize>,
        buf: &[u8],
    ) -> Result<Vec<HandshakeSequenceNumber>, Error> {
        let mut handshake_seqs = Vec::new();

        // Using DissectHandshakeIter wouldn't be appropriate here because parsing DTLS handshake
        // fragments is fallible: if there isn't enough room for a handshake fragment header, we
        // have a short read.
        let mut bound_start = bounds.start;
        let mut reader = Reader::new(buf);
        while reader.any_left() {
            let handshake_fragment = DtlsHandshakeFragment::read(&mut reader)?;
            let fragment_len =
                DTLS_HANDSHAKE_HEADER_SIZE + handshake_fragment.fragment_length.0 as usize;
            spans.push_back(FragmentSpan {
                version,
                size: Some(handshake_fragment.length.into()),
                bounds: bound_start..bound_start + fragment_len,
                dtls_fragment_fields: Some((
                    handshake_fragment.message_seq,
                    handshake_fragment.fragment_offset,
                    handshake_fragment.fragment_length,
                )),
                is_coalesced: false,
            });
            bound_start += fragment_len;
            if bound_start > bounds.end {
                return Err(Error::InvalidMessage(InvalidMessage::MessageTooLarge));
            }
            if !handshake_seqs.contains(&handshake_fragment.message_seq) {
                handshake_seqs.push(handshake_fragment.message_seq);
            }
        }

        Ok(handshake_seqs)
    }

    /// Coalesce the contents of `containing_buffer` into one or more complete DTLS handshake
    /// messages.
    ///
    /// `containing_buffer` is understood to contain some number of DTLS records containing
    /// handshake messages, i.e., a record header, then one or more handshake headers and payloads.
    /// Before calling this function, each of those records must have been parsed by
    /// [`Self::deframe`] and then input into this deframer with [`Self::input_message_dtls`].
    ///
    /// If `containing_buffer` contains all the fragments of a handshake message, then on return,
    /// the buffer will contain the coalesced (reassembled) handshake message, followed by any
    /// remaining uncoalesced fragments.
    ///
    /// If `containing_buffer` contains all the fragments of multiple handshake messages, then on
    /// return, the buffer will contain coalesced handshake messages, ordered by the handshake
    /// sequence number, not to be confused with the sequence number at the DTLS record layer.
    ///
    /// Coalesced handshake messages consist of the handshake header of the first fragment,
    /// concatenated with just the handshake payloads of subsequent fragments. Coalesced messages
    /// include `DTLSHandshake.{message_seq, fragment_offset, fragment_length}` values but these are
    /// no longer meaningful since the message is coalesced. See [1], [2] for details of the
    /// `DTLSHandshake` structure.
    ///
    /// After calling this method, callers should call [`Self::complete_span`] to find out the
    /// position of the next coalesced handshake message, if any, and then [`Self::message`] to
    /// obtain it.
    ///
    /// More fragments may then be added into the deframer by calling [`Self::deframe`] and
    /// [`Self::input_message_dtls`] again.
    ///
    /// [1]: https://datatracker.ietf.org/doc/html/rfc6347#section-4.2.2
    /// [2]: https://datatracker.ietf.org/doc/html/rfc9147#section-5.2
    fn coalesce(
        &mut self,
        spans: &mut VecDeque<FragmentSpan>,
        containing_buffer: &mut [u8],
    ) -> Result<(), InvalidMessage> {
        // Sort the spans by sequence number and fragment offset so we can reorder
        // containing_buffer.
        spans
            .make_contiguous()
            .sort_by(|left, right| {
                // Unwrap safety: this method should only be used for DTLS, in which case these
                // fields are always set
                let (left_seq, left_fragment_offset, _) = left.dtls_fragment_fields.unwrap();
                let (right_seq, right_fragment_offset, _) = right.dtls_fragment_fields.unwrap();

                (left_seq, left_fragment_offset).cmp(&(right_seq, right_fragment_offset))
            });

        // Scratch buffer to hold fragments while we slide the rest of `containing_buffer` around.
        // 4096 is chosen because it's _probably_ bigger than the PMTU anyone will use and thus
        // _probably_ big enough for any DTLS fragment we'll encounter.
        // TODO(timg): We shouldn't make guesses about PMTU here. Make this a smaller buffer, say
        // 1024 bytes, and then do the copy-aside-and-slide-containing-buffer dance one chunk at
        // a time.
        let mut scratch = [0u8; 4096];

        // Which handshake message are we reassembling into?
        let mut first_fragment_index = 0;
        // How much of the current handshake message have we reassembled (excluding handshake
        // headers)?
        let mut current_message_len = 0;
        // How many bytes of handshake message have we reassembled, total, including the first
        // fragment's handshake header but excluding any headers from subsequent messages?
        // Equivalentlty, what position of containing_buffer are we copying into?
        let mut reassembled_len = 0;

        // We can't idiomatically iterate over self.spans because we need to mutably borrow elements
        // besides the current one in the loop body.
        for index in 0..spans.len() {
            let (current_seq, U24(current_fragment_offset), U24(current_fragment_length)) = spans
                [index]
                .dtls_fragment_fields
                .unwrap();

            let (coalesce_into_seq, coalsce_into_offset, _) = spans[first_fragment_index]
                .dtls_fragment_fields
                .unwrap();

            let is_first_fragment = index == 0 || current_seq > coalesce_into_seq;
            if is_first_fragment {
                first_fragment_index = index;
                current_message_len = 0;
            }

            if current_fragment_offset > current_message_len {
                // We are still missing some fragments and can't yet reassemble this handshake.
                break;
            }

            // Figure out what portion of the current handshake fragment we'll copy aside and back
            // into containing_buffer.
            let mut copy_bounds = spans[index].bounds.clone();

            // Each span's bounds include only the handshake header and the handshake message
            // fragment. We retain the handshake header for the first fragment of each handshake
            // message, but skip it for subsequent fragments. As a result, after decoalescing,
            // we'll have what appears to be a single handshake message.
            if !is_first_fragment {
                copy_bounds.start += spans[index]
                    .version
                    .handshake_header_size();
            }

            // DTLS handshake fragments may overlap, so work out what portion of this span to append
            let overlap = current_message_len - current_fragment_offset;
            copy_bounds.start += overlap as usize;
            current_message_len += current_fragment_length - overlap;

            if !is_first_fragment {
                // Grow the fragment we coalesce into and mark the fragment we coalesced from for
                // pruning.
                spans[first_fragment_index].bounds.end += copy_bounds.len();
                spans[first_fragment_index].dtls_fragment_fields = Some((
                    coalesce_into_seq,
                    coalsce_into_offset,
                    U24(current_message_len),
                ));
                spans[index].is_coalesced = true;
            }

            // Copy the fragment we want into scratch.
            scratch[0..copy_bounds.len()].copy_from_slice(&containing_buffer[copy_bounds.clone()]);

            // If there is any portion of containing_buffer between the fragment we coalesce into
            // and the fragment we are copying, shift that portion to the right to make room. The
            // span might be preceded by a record header, but we don't need to preserve it.
            let curr_fragment_start = spans[index].bounds.start;
            if curr_fragment_start > reassembled_len {
                let shifted_range = reassembled_len..curr_fragment_start;
                let dest = reassembled_len + copy_bounds.len();
                containing_buffer.copy_within(shifted_range.clone(), dest);

                // Fix up bounds of all spans in the portion that got shifted.
                for span in spans.iter_mut() {
                    if shifted_range.contains(&span.bounds.start)
                        && shifted_range.contains(&(span.bounds.end - 1))
                    {
                        span.bounds.start += copy_bounds.len();
                        span.bounds.end += copy_bounds.len();
                    }
                }

                // And of any future records
                for future_record in &mut self.future_epoch_records {
                    if shifted_range.contains(&future_record.bounds.start)
                        && shifted_range.contains(&(future_record.bounds.end - 1))
                    {
                        future_record.bounds.start += copy_bounds.len();
                        future_record.bounds.end += copy_bounds.len();
                    }
                }
            }

            // Copy the span we want from scratch back into containing_buffer
            let destination_bounds = reassembled_len..reassembled_len + copy_bounds.len();
            containing_buffer[destination_bounds.clone()]
                .copy_from_slice(&scratch[0..copy_bounds.len()]);

            if is_first_fragment {
                // We may have copied the first fragment to a new position, so fix up its bounds
                spans[index].bounds = destination_bounds;
            }

            reassembled_len += copy_bounds.len();
        }

        // Remove spans which have been coalesced into other spans so we don't have to deal with
        // them later. Iterate in reverse so we can use Vec::remove without invalidating indices.
        for index in (0..spans.len()).rev() {
            if spans[index].is_coalesced {
                spans.remove(index);
            }
        }

        Ok(())
    }
}

impl Default for DtlsDeframerCore {
    fn default() -> Self {
        Self {
            // TODO(DTLS): choose a reasonable number of future epoch messages to buffer
            future_epoch_records: VecDeque::with_capacity(16),
        }
    }
}

/// A deframed message from a future epoch.
#[derive(Clone, Debug)]
struct FutureEpochDeframed {
    bounds: Range<usize>,
    epoch: Epoch,
}
