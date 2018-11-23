/**
 * nGram tokenizer implementation for Kakao nGram Search
 */

#pragma once

#include "mongo/base/disallow_copying.h"
#include "mongo/base/string_data.h"
#include "mongo/db/fts/fts_tokenizer.h"
#include "mongo/db/fts/stemmer.h"
#include "mongo/db/fts/tokenizer.h"
#include "mongo/db/fts/unicode/string.h"

namespace mongo {
namespace fts {

class FTSLanguage;
class StopWords;

/**
 * UnicodeFTSTokenizer
 * A iterator of "documents" where a document contains words delimited by a predefined set of
 * Unicode delimiters (see gen_delimiter_list.py)
 * Uses
 * - A list of Unicode delimiters for tokenizing words (see gen_delimiter_list.py).
 * - tolower from mongo::unicode, which supports UTF-8 simple and Turkish case folding
 * - Stemmer (ie, Snowball Stemmer) to stem words.
 * - Embeded stop word lists for each language in StopWord class
 *
 * For each word returns a stem version of a word optimized for full text indexing.
 * Optionally supports returning case sensitive search terms.
 */
class UnicodeNgramFTSTokenizer final : public FTSTokenizer {
    MONGO_DISALLOW_COPYING(UnicodeNgramFTSTokenizer);

public:
    UnicodeNgramFTSTokenizer(const FTSLanguage* language);

    void reset(StringData document, Options options) override;

    bool moveNext() override;

    StringData get() const override;

private:
    /**
     * Helper that moves the tokenizer past all delimiters that shouldn't be considered part of
     * tokens.
     */
    void _skipDelimiters();
    bool moveNextForDelimiter();
    bool moveNextForNgram();

    const FTSLanguage* const _language;
    const unicode::CaseFoldMode _caseFoldMode;

    unicode::String _document;
    size_t _pos;
    StringData _word;
    Options _options;

    StackBufBuilder _wordBuf;
    StackBufBuilder _finalBuf;
};

}  // namespace fts
}  // namespace mongo
