import os
import logging
from os.path import (
	isdir,
	splitext,
)
from pyglossary.compression import compressionOpen as c_open

log = logging.getLogger("pyglossary")

file_size_check_every = 100


class TextGlossaryWriter(object):
	_encoding: str = "utf-8"
	_newline: str = "\n"
	_wordListEncodeFunc: "Optional[Callable[[List[str]], str]]" = None
	_wordEscapeFunc: "Optional[Callable[[str], str]]" = None
	_defiEscapeFunc: "Optional[Callable[[str], str]]" = None
	_ext: str = ".txt"
	_head: str = ""
	_tail: str = ""
	_resources: bool = True
	_file_size_approx: int = 0
	_word_title: bool = False

	def __init__(
		self,
		glos: "GlossaryType",
		entryFmt: str = "",  # contain {word} and {defi}
		writeInfo: bool = True,
		outInfoKeysAliasDict: "Optional[Dict[str, str]]" = None,
	) -> None:
		self._glos = glos
		self._filename = ""
		self._file = None
		self._resDir = ""

		if not entryFmt:
			raise ValueError("entryFmt argument is missing")

		self._entryFmt = entryFmt
		self._writeInfo = writeInfo

		if not outInfoKeysAliasDict:
			outInfoKeysAliasDict = {}
		self._outInfoKeysAliasDict = outInfoKeysAliasDict
		# TODO: replace outInfoKeysAliasDict arg with a func?

	def setAttrs(
		self,
		encoding=None,
		newline=None,
		wordListEncodeFunc=None,
		wordEscapeFunc=None,
		defiEscapeFunc=None,
		ext=None,
		head=None,
		tail=None,
		resources=None,
		word_title=None,
		file_size_approx=None,
	):
		if encoding is not None:
			self._encoding = encoding
		if newline is not None:
			self._newline = newline
		if wordListEncodeFunc is not None:
			self._wordListEncodeFunc = wordListEncodeFunc
		if wordEscapeFunc is not None:
			self._wordEscapeFunc = wordEscapeFunc
		if defiEscapeFunc is not None:
			self._defiEscapeFunc = defiEscapeFunc
		if ext is not None:
			self._ext = ext
		if head is not None:
			self._head = head
		if tail is not None:
			self._tail = tail
		if resources is not None:
			self._resources = resources
		if word_title is not None:
			self._word_title = word_title
		if file_size_approx is not None:
			self._file_size_approx = file_size_approx

	def open(self, filename: str) -> None:
		if self._file_size_approx > 0:
			self._glos.setInfo("file_count", "-1")
		self._open(filename)
		self._filename = filename
		self._resDir = f"{filename}_res"
		if not isdir(self._resDir):
			os.mkdir(self._resDir)

	def _open(self, filename: str):
		if not filename:
			filename = self._glos.filename + self._ext

		_file = self._file = c_open(
			filename,
			mode="wt",
			encoding=self._encoding,
			newline=self._newline,
		)
		_file.write(self._head)
		if self._writeInfo:
			entryFmt = self._entryFmt
			outInfoKeysAliasDict = self._outInfoKeysAliasDict
			wordEscapeFunc = self._wordEscapeFunc
			defiEscapeFunc = self._defiEscapeFunc
			for key, value in self._glos.iterInfo():
				# both key and value are supposed to be non-empty string
				if not (key and value):
					log.warning(f"skipping info {key=}, {value=}")
					continue
				key = outInfoKeysAliasDict.get(key, key)
				if not key:
					continue
				word = f"##{key}"
				if wordEscapeFunc is not None:
					word = wordEscapeFunc(word)
					if not word:
						continue
				if defiEscapeFunc is not None:
					value = defiEscapeFunc(value)
					if not value:
						continue
				_file.write(entryFmt.format(
					word=word,
					defi=value,
				))
		_file.flush()
		return _file

	def write(self):
		glos = self._glos
		_file = self._file
		entryFmt = self._entryFmt
		wordListEncodeFunc = self._wordListEncodeFunc
		wordEscapeFunc = self._wordEscapeFunc
		defiEscapeFunc = self._defiEscapeFunc
		resources = self._resources
		word_title = self._word_title

		file_size_approx = self._file_size_approx
		entryCount = 0
		fileIndex = 0

		while True:
			entry = yield
			if entry is None:
				break
			if entry.isData():
				if resources:
					entry.save(self._resDir)
				continue

			word = entry.s_word
			defi = entry.defi

			# if glos.alts:  # FIXME

			if word_title:
				defi = glos.wordTitleStr(entry.l_word[0]) + defi

			if wordListEncodeFunc is not None:
				word = wordListEncodeFunc(entry.l_word)
			elif wordEscapeFunc is not None:
				word = wordEscapeFunc(word)

			if defiEscapeFunc is not None:
				defi = defiEscapeFunc(defi)
			_file.write(entryFmt.format(word=word, defi=defi))

			if file_size_approx > 0:
				entryCount += 1
				if entryCount % file_size_check_every == 0:
					if _file.tell() >= file_size_approx:
						fileIndex += 1
						_file = self._open(f"{self._filename}.{fileIndex}")

	def finish(self):
		if self._tail:
			self._file.write(self._tail)
		self._file.close()
		if not os.listdir(self._resDir):
			os.rmdir(self._resDir)


def writeTxt(
	glos: "GlossaryType",
	entryFmt: str = "",  # contain {word} and {defi}
	filename: str = "",
	writeInfo: bool = True,
	wordEscapeFunc: "Optional[Callable]" = None,
	defiEscapeFunc: "Optional[Callable]" = None,
	ext: str = ".txt",
	head: str = "",
	tail: str = "",
	outInfoKeysAliasDict: "Optional[Dict[str, str]]" = None,
	encoding: str = "utf-8",
	newline: str = "\n",
	resources: bool = True,
	word_title: bool = False,
) -> "Generator[None, BaseEntry, None]":
	writer = TextGlossaryWriter(
		glos,
		entryFmt=entryFmt,
		writeInfo=writeInfo,
		outInfoKeysAliasDict=outInfoKeysAliasDict,
	)
	writer.setAttrs(
		encoding=encoding,
		newline=newline,
		wordEscapeFunc=wordEscapeFunc,
		defiEscapeFunc=defiEscapeFunc,
		ext=ext,
		head=head,
		tail=tail,
		resources=resources,
		word_title=word_title,
	)
	writer.open(filename)
	yield from writer.write()
	writer.finish()


def writeTabfile(
	glos: "GlossaryType",
	filename: str = "",
	encoding: str = "utf-8",
	resources: bool = True,
) -> "Generator[None, BaseEntry, None]":
	from pyglossary.text_utils import escapeNTB
	writer = TextGlossaryWriter(
		glos,
		entryFmt="{word}\t{defi}\n",
		outInfoKeysAliasDict=None,
	)
	writer.setAttrs(
		encoding=encoding,
		wordEscapeFunc=escapeNTB,
		defiEscapeFunc=escapeNTB,
		ext=".txt",
		resources=resources,
	)
	writer.open(filename)
	yield from writer.write()
	writer.finish()
