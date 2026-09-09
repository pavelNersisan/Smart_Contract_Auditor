import { useRef, useState } from 'react'
import { fetchVerifiedSource } from '../utils/etherscan.js'

const SAMPLE = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Vault {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
        balances[msg.sender] = 0;
    }

    receive() external payable {}
}
`

export default function ContractUpload({ onSubmit, busy }) {
  const [source, setSource] = useState('')
  const [filename, setFilename] = useState('Contract.sol')
  const [address, setAddress] = useState('')
  const [apiKey, setApiKey] = useState('')
  const [note, setNote] = useState('')
  const fileRef = useRef(null)

  const readFile = (file) => {
    if (!file) return
    setFilename(file.name.endsWith('.sol') ? file.name : `${file.name}.sol`)
    const reader = new FileReader()
    reader.onload = () => setSource(String(reader.result || ''))
    reader.onerror = () => setNote('Could not read that file.')
    reader.readAsText(file)
  }

  const loadFromChain = async () => {
    setNote('')
    if (!/^0x[0-9a-fA-F]{40}$/.test(address)) {
      setNote('Enter a valid 0x… contract address.')
      return
    }
    setNote('Fetching verified source from Etherscan…')
    try {
      const data = await fetchVerifiedSource(address, apiKey)
      setSource(data.source)
      setFilename(data.name ? `${data.name}.sol` : 'Contract.sol')
      setNote(`Loaded ${data.name || 'contract'} (${data.compilerVersion || 'unknown compiler'}).`)
    } catch (err) {
      setNote(err.message)
    }
  }

  const submit = (event) => {
    event.preventDefault()
    setNote('')
    if (!source.trim()) {
      setNote('Paste a contract, upload a .sol file, or load one from Etherscan.')
      return
    }
    onSubmit({ filename, source })
  }

  return (
    <form className="card upload" onSubmit={submit}>
      <div className="card-title">
        <h2>Contract</h2>
        <div className="upload-actions">
          <button type="button" className="ghost" onClick={() => { setSource(SAMPLE); setFilename('Vault.sol') }}>
            Load vulnerable sample
          </button>
          <button type="button" className="ghost" onClick={() => fileRef.current?.click()}>
            Upload .sol
          </button>
          <input
            ref={fileRef}
            type="file"
            accept=".sol,text/plain"
            hidden
            onChange={(e) => readFile(e.target.files?.[0])}
          />
        </div>
      </div>

      <input
        className="filename"
        value={filename}
        onChange={(e) => setFilename(e.target.value)}
        aria-label="File name"
      />
      <textarea
        className="source"
        spellCheck={false}
        placeholder="// SPDX-License-Identifier: MIT&#10;pragma solidity ^0.8.0;&#10;&#10;contract YourContract { … }"
        value={source}
        onChange={(e) => setSource(e.target.value)}
      />

      <div className="etherscan">
        <input
          placeholder="0x… contract address (optional)"
          value={address}
          onChange={(e) => setAddress(e.target.value)}
        />
        <input
          placeholder="Etherscan API key (optional)"
          value={apiKey}
          onChange={(e) => setApiKey(e.target.value)}
        />
        <button type="button" className="ghost" onClick={loadFromChain}>
          Fetch source
        </button>
      </div>

      {note && <div className="hint">{note}</div>}

      <div className="submit-row">
        <button type="submit" className="primary" disabled={busy}>
          {busy ? 'Analysing…' : 'Run audit'}
        </button>
        <span className="hint">{source.length.toLocaleString()} characters</span>
      </div>
    </form>
  )
}
