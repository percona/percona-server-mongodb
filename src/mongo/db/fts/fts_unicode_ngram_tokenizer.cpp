/**
 * nGram tokenizer implementation for Kakao nGram Search
 */

#define MONGO_LOG_DEFAULT_COMPONENT ::mongo::logger::LogComponent::kDefault

#include "mongo/platform/basic.h"

#include "mongo/db/fts/fts_unicode_ngram_tokenizer.h"

#include "mongo/db/fts/fts_query_impl.h"
#include "mongo/db/fts/fts_spec.h"
#include "mongo/db/fts/stemmer.h"
#include "mongo/db/fts/stop_words.h"
#include "mongo/db/fts/tokenizer.h"
#include "mongo/stdx/memory.h"
#include "mongo/util/mongoutils/str.h"
#include "mongo/util/stringutils.h"
#include "mongo/util/log.h"

/**
 * NGram token size is always 2
 *   If ngram_token_size is greater than 3, mongodb ngram can't search 2-character term.
 *   So, ngram_token_size=2 is best choice for general purpose.
 */
#define NGRAM_TOKEN_SIZE 2


namespace mongo {
namespace fts {

using std::string;

/**
 * Regarding only below white-space characters as token delimiter.
 *
 * 0x09 : HORIZONTAL-TAB
 * 0x0a : LINE-FEED (\n)
 * 0x0b : VERTICAL-TAB
 * 0x0d : CARRIAGE-RETURN (\r)
 * 0x20 : SPACE
 */
bool codepointIsDelimiter(char32_t codepoint){
    if (codepoint <= 0x7f) {
      if(codepoint==0x09 || codepoint==0x0a || codepoint==0x0b || codepoint==0x0d || codepoint==0x20)
        return true;
    }

    return false;
}

UnicodeNgramFTSTokenizer::UnicodeNgramFTSTokenizer(const FTSLanguage* language)
    : _language(language),
      _caseFoldMode(_language->str() == "turkish" ? unicode::CaseFoldMode::kTurkish
                                                  : unicode::CaseFoldMode::kNormal) {}

void UnicodeNgramFTSTokenizer::reset(StringData document, Options options) {
    _options = options;
    _pos = 0;
    _document.resetData(document);  // Validates that document is valid UTF8.

    // Skip any leading delimiters (and handle the case where the document is entirely delimiters).
    _skipDelimiters();
}

bool UnicodeNgramFTSTokenizer::moveNext() {
    bool hasToken = false;

    if(_options & kGenerateDelimiterTokensForNGram){
        hasToken = moveNextForDelimiter();
    }else{
        hasToken = moveNextForNgram();
    }

    return hasToken;
}

bool UnicodeNgramFTSTokenizer::moveNextForNgram(){
    while (true) {
        if (_pos >= _document.size()) {
            _word = "";
            return false;
        }

        // Traverse through non-delimiters and build the next token.
        size_t start = _pos;
        while (_pos < _document.size()) {
            if(codepointIsDelimiter(_document[_pos])){
                // Not sufficient characters for NGRAM_TOKEN_SIZE, Ignore this and move DELIMITER-TOKEN
                _skipDelimiters();
                start = _pos;
                continue;
            }

            if(_pos - start >= NGRAM_TOKEN_SIZE-1){
                break;
            }
            _pos++;
        }

        if (_pos >= _document.size()) {
            _word = "";
            return false;
        }

        // set next n-gram token start point
        _pos = start + 1;

        // Skip the delimiters before the next token.
        _skipDelimiters();

        if (_options & kGenerateCaseSensitiveTokens) {
            _word = _document.substrToBuf(&_wordBuf, start, NGRAM_TOKEN_SIZE);
        }else{
            _word = _document.toLowerToBuf(&_wordBuf, _caseFoldMode, start, NGRAM_TOKEN_SIZE);
        }

        if (!(_options & kGenerateDiacriticSensitiveTokens)) {
            // Can't use _wordbuf for output here because our input _word may point into it.
            _word = unicode::String::caseFoldAndStripDiacritics(
                &_finalBuf, _word, unicode::String::kCaseSensitive, _caseFoldMode);
        }

        return true;
    }
}

/**
 * This method is used for phrase matcher
 *
 * And this method is come from UnicodeFTSTokenizer::moveNext() with small changes
 */
bool UnicodeNgramFTSTokenizer::moveNextForDelimiter() {
    while (true) {
        if (_pos >= _document.size()) {
            _word = "";
            return false;
        }

        // Traverse through non-delimiters and build the next token.
        size_t start = _pos++;
        while (_pos < _document.size() &&
               (!codepointIsDelimiter(_document[_pos]))) {
            ++_pos;
        }
        const size_t len = _pos - start;

        // Skip the delimiters before the next token.
        _skipDelimiters();

        if (_options & kGenerateCaseSensitiveTokens) {
            _word = _document.substrToBuf(&_wordBuf, start, len);
        }else{
            _word = _document.toLowerToBuf(&_wordBuf, _caseFoldMode, start, len);
        }

        // No stemming in NGram tokenizer
        // The stemmer is diacritic sensitive, so stem the word before removing diacritics.
        // _word = _stemmer.stem(_word);

        if (!(_options & kGenerateDiacriticSensitiveTokens)) {
            // Can't use _wordbuf for output here because our input _word may point into it.
            _word = unicode::String::caseFoldAndStripDiacritics(
                &_finalBuf, _word, unicode::String::kCaseSensitive, _caseFoldMode);
        }

        return true;
    }
}

StringData UnicodeNgramFTSTokenizer::get() const {
    return _word;
}

void UnicodeNgramFTSTokenizer::_skipDelimiters() {
    while (_pos < _document.size() && codepointIsDelimiter(_document[_pos])) {
        ++_pos;
    }
}

}  // namespace fts
}  // namespace mongo
