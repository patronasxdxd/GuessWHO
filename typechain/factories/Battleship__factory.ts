/* Autogenerated file. Do not edit manually. */
/* tslint:disable */
/* eslint-disable */

import { Signer, utils, Contract, ContractFactory, Overrides } from "ethers";
import { Provider, TransactionRequest } from "@ethersproject/providers";
import type { Battleship, BattleshipInterface } from "../Battleship";

const _abi = [
  {
    inputs: [
      {
        internalType: "contract ICreateVerifier",
        name: "_createVerifier",
        type: "address",
      },
      {
        internalType: "contract IMoveVerifier",
        name: "_moveVerifier",
        type: "address",
      },
    ],
    stateMutability: "nonpayable",
    type: "constructor",
  },
  {
    inputs: [
      {
        internalType: "bytes",
        name: "_proof",
        type: "bytes",
      },
      {
        internalType: "uint256",
        name: "_boardHash",
        type: "uint256",
      },
    ],
    name: "createGame",
    outputs: [
      {
        internalType: "uint32",
        name: "",
        type: "uint32",
      },
    ],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [],
    name: "createVerifier",
    outputs: [
      {
        internalType: "contract ICreateVerifier",
        name: "",
        type: "address",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "uint32",
        name: "_gameID",
        type: "uint32",
      },
    ],
    name: "game",
    outputs: [
      {
        components: [
          {
            internalType: "address",
            name: "player1",
            type: "address",
          },
          {
            internalType: "address",
            name: "player2",
            type: "address",
          },
          {
            internalType: "uint256",
            name: "player1Hash",
            type: "uint256",
          },
          {
            internalType: "uint256",
            name: "player2Hash",
            type: "uint256",
          },
          {
            components: [
              {
                internalType: "uint256",
                name: "x",
                type: "uint256",
              },
              {
                internalType: "uint256",
                name: "y",
                type: "uint256",
              },
              {
                internalType: "bool",
                name: "isHit",
                type: "bool",
              },
            ],
            internalType: "struct Battleship.Move[]",
            name: "moves",
            type: "tuple[]",
          },
        ],
        internalType: "struct Battleship.GamePublicMetadata",
        name: "",
        type: "tuple",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "uint32",
        name: "_gameID",
        type: "uint32",
      },
      {
        internalType: "bytes",
        name: "_proof",
        type: "bytes",
      },
      {
        internalType: "uint256",
        name: "_boardHash",
        type: "uint256",
      },
    ],
    name: "joinGame",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [],
    name: "moveVerifier",
    outputs: [
      {
        internalType: "contract IMoveVerifier",
        name: "",
        type: "address",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "uint32",
        name: "_gameID",
        type: "uint32",
      },
      {
        internalType: "uint256",
        name: "_moveX",
        type: "uint256",
      },
      {
        internalType: "uint256",
        name: "_moveY",
        type: "uint256",
      },
      {
        internalType: "bytes",
        name: "_proof",
        type: "bytes",
      },
      {
        internalType: "bool",
        name: "isPreviousMoveAHit",
        type: "bool",
      },
    ],
    name: "submitMove",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
];

const _bytecode =
  "0x60c06040523480156200001157600080fd5b50604051620023f4380380620023f48339818101604052810190620000379190620000db565b8173ffffffffffffffffffffffffffffffffffffffff1660808173ffffffffffffffffffffffffffffffffffffffff1660601b815250508073ffffffffffffffffffffffffffffffffffffffff1660a08173ffffffffffffffffffffffffffffffffffffffff1660601b815250505050620001ac565b600081519050620000be8162000178565b92915050565b600081519050620000d58162000192565b92915050565b60008060408385031215620000ef57600080fd5b6000620000ff85828601620000ad565b92505060206200011285828601620000c4565b9150509250929050565b6000620001298262000158565b9050919050565b60006200013d826200011c565b9050919050565b600062000151826200011c565b9050919050565b600073ffffffffffffffffffffffffffffffffffffffff82169050919050565b620001838162000130565b81146200018f57600080fd5b50565b6200019d8162000144565b8114620001a957600080fd5b50565b60805160601c60a05160601c61220e620001e660003960008181610b0a0152610eac01526000818161038c0152610b41015261220e6000f3fe608060405234801561001057600080fd5b50600436106100625760003560e01c80631ea6beb614610067578063453827c614610083578063849cfef4146100a1578063ac744a2c146100d1578063c894cafe14610101578063d173bf9c1461011d575b600080fd5b610081600480360381019061007c91906114a2565b61013b565b005b61008b61038a565b6040516100989190611ab1565b60405180910390f35b6100bb60048036038101906100b69190611421565b6103ae565b6040516100c89190611c09565b60405180910390f35b6100eb60048036038101906100e69190611479565b610495565b6040516100f89190611be7565b60405180910390f35b61011b6004803603810190610116919061150e565b61074c565b005b610125610b08565b6040516101329190611acc565b60405180910390f35b60008463ffffffff161015610185576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161017c90611b27565b60405180910390fd5b60008054906101000a900463ffffffff1663ffffffff168463ffffffff16106101e3576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016101da90611b27565b60405180910390fd5b6000600160008663ffffffff1663ffffffff16815260200190815260200160002090503373ffffffffffffffffffffffffffffffffffffffff168160000160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff161415610299576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161029090611b87565b60405180910390fd5b600073ffffffffffffffffffffffffffffffffffffffff168160010160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff161461032c576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161032390611ae7565b60405180910390fd5b610337848484610b2c565b338160010160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055508181600301819055505050505050565b7f000000000000000000000000000000000000000000000000000000000000000081565b60006103bb848484610b2c565b60008060009054906101000a900463ffffffff16905060016000808282829054906101000a900463ffffffff166103f29190611dce565b92506101000a81548163ffffffff021916908363ffffffff1602179055506000600160008363ffffffff1663ffffffff1681526020019081526020016000209050338160000160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055508381600201819055506000816005018190555081925050509392505050565b61049d611228565b60008263ffffffff1610156104e7576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016104de90611b27565b60405180910390fd5b60008054906101000a900463ffffffff1663ffffffff168263ffffffff1610610545576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161053c90611b27565b60405180910390fd5b6000600160008463ffffffff1663ffffffff16815260200190815260200160002090506000816005015467ffffffffffffffff8111156105ae577f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b6040519080825280602002602001820160405280156105e757816020015b6105d4611283565b8152602001906001900390816105cc5790505b50905060005b826005015481101561069f5782600401600082815260200190815260200160002060405180606001604052908160008201548152602001600182015481526020016002820160009054906101000a900460ff161515151581525050828281518110610681577f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b6020026020010181905250808061069790611f0d565b9150506105ed565b506040518060a001604052808360000160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020018360010160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200183600201548152602001836003015481526020018281525092505050919050565b60008663ffffffff161015610796576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161078d90611b27565b60405180910390fd5b60008054906101000a900463ffffffff1663ffffffff168663ffffffff16106107f4576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016107eb90611b27565b60405180910390fd5b6000600160008863ffffffff1663ffffffff16815260200190815260200160002090506000816002015490506000600283600501546108339190611f56565b14156108d0578160000160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff16146108cb576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016108c290611bc7565b60405180910390fd5b61096a565b8160010160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff1614610962576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161095990611bc7565b60405180910390fd5b816003015490505b6000871015801561097b5750600a87105b6109ba576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016109b190611ba7565b60405180910390fd5b600086101580156109cb5750600a86105b610a0a576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401610a0190611b67565b60405180910390fd5b600082600501541115610a7457600082600401600060018560050154610a309190611e08565b81526020019081526020016000209050610a568686848785600001548660010154610e97565b838160020160006101000a81548160ff021916908315150217905550505b60405180606001604052808881526020018781526020016000151581525082600401600084600501548152602001908152602001600020600082015181600001556020820151816001015560408201518160020160006101000a81548160ff0219169083151502179055509050506001826005016000828254610af79190611d78565b925050819055505050505050505050565b7f000000000000000000000000000000000000000000000000000000000000000081565b60008383810190610b3d91906113ce565b90507f000000000000000000000000000000000000000000000000000000000000000073ffffffffffffffffffffffffffffffffffffffff166343753b4d604051806040016040528084600060088110610bc0577f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b6020020151815260200184600160088110610c04577f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b60200201518152506040518060400160405280604051806040016040528087600260088110610c5c577f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b6020020151815260200187600360088110610ca0577f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b60200201518152508152602001604051806040016040528087600460088110610cf2577f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b6020020151815260200187600560088110610d36577f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b6020020151815250815250604051806040016040528086600660088110610d86577f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b6020020151815260200186600760088110610dca577f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b60200201518152506040518060200160405280888152506040518563ffffffff1660e01b8152600401610e009493929190611a23565b602060405180830381600087803b158015610e1a57600080fd5b505af1158015610e2e573d6000803e3d6000fd5b505050506040513d601f19601f82011682018060405250810190610e5291906113f8565b610e91576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401610e8890611b07565b60405180910390fd5b50505050565b60008686810190610ea891906113ce565b90507f000000000000000000000000000000000000000000000000000000000000000073ffffffffffffffffffffffffffffffffffffffff16635fe8c13b604051806040016040528084600060088110610f2b577f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b6020020151815260200184600160088110610f6f577f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b60200201518152506040518060400160405280604051806040016040528087600260088110610fc7577f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b602002015181526020018760036008811061100b577f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b6020020151815250815260200160405180604001604052808760046008811061105d577f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b60200201518152602001876005600881106110a1577f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b60200201518152508152506040518060400160405280866006600881106110f1577f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b6020020151815260200186600760088110611135577f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b602002015181525060405180608001604052808a611154576000611157565b60015b60ff1681526020018b8152602001898152602001888152506040518563ffffffff1660e01b815260040161118e9493929190611a6a565b602060405180830381600087803b1580156111a857600080fd5b505af11580156111bc573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906111e091906113f8565b61121f576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161121690611b47565b60405180910390fd5b50505050505050565b6040518060a00160405280600073ffffffffffffffffffffffffffffffffffffffff168152602001600073ffffffffffffffffffffffffffffffffffffffff1681526020016000815260200160008152602001606081525090565b604051806060016040528060008152602001600081526020016000151581525090565b60006112b96112b484611c49565b611c24565b905080828560208602820111156112cf57600080fd5b60005b858110156112ff57816112e588826113a4565b8452602084019350602083019250506001810190506112d2565b5050509392505050565b600082601f83011261131a57600080fd5b60086113278482856112a6565b91505092915050565b60008135905061133f81612193565b92915050565b60008151905061135481612193565b92915050565b60008083601f84011261136c57600080fd5b8235905067ffffffffffffffff81111561138557600080fd5b60208301915083600182028301111561139d57600080fd5b9250929050565b6000813590506113b3816121aa565b92915050565b6000813590506113c8816121c1565b92915050565b600061010082840312156113e157600080fd5b60006113ef84828501611309565b91505092915050565b60006020828403121561140a57600080fd5b600061141884828501611345565b91505092915050565b60008060006040848603121561143657600080fd5b600084013567ffffffffffffffff81111561145057600080fd5b61145c8682870161135a565b9350935050602061146f868287016113a4565b9150509250925092565b60006020828403121561148b57600080fd5b6000611499848285016113b9565b91505092915050565b600080600080606085870312156114b857600080fd5b60006114c6878288016113b9565b945050602085013567ffffffffffffffff8111156114e357600080fd5b6114ef8782880161135a565b93509350506040611502878288016113a4565b91505092959194509250565b60008060008060008060a0878903121561152757600080fd5b600061153589828a016113b9565b965050602061154689828a016113a4565b955050604061155789828a016113a4565b945050606087013567ffffffffffffffff81111561157457600080fd5b61158089828a0161135a565b9350935050608061159389828a01611330565b9150509295509295509295565b60006115ac8383611703565b60408301905092915050565b60006115c483836119c3565b60608301905092915050565b60006115dc8383611a05565b60208301905092915050565b6115f181611e3c565b82525050565b61160081611ca7565b61160a8184611d1f565b925061161582611c6f565b8060005b8381101561164657815161162d87826115a0565b965061163883611cde565b925050600181019050611619565b505050505050565b600061165982611cb2565b6116638185611d2a565b935061166e83611c79565b8060005b8381101561169f57815161168688826115b8565b975061169183611ceb565b925050600181019050611672565b5085935050505092915050565b6116b581611cbd565b6116bf8184611d3b565b92506116ca82611c89565b8060005b838110156116fb5781516116e287826115d0565b96506116ed83611cf8565b9250506001810190506116ce565b505050505050565b61170c81611cc8565b6117168184611d46565b925061172182611c93565b8060005b8381101561175257815161173987826115d0565b965061174483611d05565b925050600181019050611725565b505050505050565b61176381611cc8565b61176d8184611d51565b925061177882611c93565b8060005b838110156117a957815161179087826115d0565b965061179b83611d05565b92505060018101905061177c565b505050505050565b6117ba81611cd3565b6117c48184611d5c565b92506117cf82611c9d565b8060005b838110156118005781516117e787826115d0565b96506117f283611d12565b9250506001810190506117d3565b505050505050565b61181181611e4e565b82525050565b61182081611e94565b82525050565b61182f81611eb8565b82525050565b6000611842600c83611d67565b915061184d82612025565b602082019050919050565b6000611865601883611d67565b91506118708261204e565b602082019050919050565b6000611888600f83611d67565b915061189382612077565b602082019050919050565b60006118ab601183611d67565b91506118b6826120a0565b602082019050919050565b60006118ce601083611d67565b91506118d9826120c9565b602082019050919050565b60006118f1602183611d67565b91506118fc826120f2565b604082019050919050565b6000611914601083611d67565b915061191f82612141565b602082019050919050565b6000611937600e83611d67565b91506119428261216a565b602082019050919050565b600060a08301600083015161196560008601826115e8565b50602083015161197860208601826115e8565b50604083015161198b6040860182611a05565b50606083015161199e6060860182611a05565b50608083015184820360808601526119b6828261164e565b9150508091505092915050565b6060820160008201516119d96000850182611a05565b5060208201516119ec6020850182611a05565b5060408201516119ff6040850182611808565b50505050565b611a0e81611e7a565b82525050565b611a1d81611e84565b82525050565b600061012082019050611a39600083018761175a565b611a4660408301866115f7565b611a5360c083018561175a565b611a616101008301846116ac565b95945050505050565b600061018082019050611a80600083018761175a565b611a8d60408301866115f7565b611a9a60c083018561175a565b611aa86101008301846117b1565b95945050505050565b6000602082019050611ac66000830184611817565b92915050565b6000602082019050611ae16000830184611826565b92915050565b60006020820190508181036000830152611b0081611835565b9050919050565b60006020820190508181036000830152611b2081611858565b9050919050565b60006020820190508181036000830152611b408161187b565b9050919050565b60006020820190508181036000830152611b608161189e565b9050919050565b60006020820190508181036000830152611b80816118c1565b9050919050565b60006020820190508181036000830152611ba0816118e4565b9050919050565b60006020820190508181036000830152611bc081611907565b9050919050565b60006020820190508181036000830152611be08161192a565b9050919050565b60006020820190508181036000830152611c01818461194d565b905092915050565b6000602082019050611c1e6000830184611a14565b92915050565b6000611c2e611c3f565b9050611c3a8282611edc565b919050565b6000604051905090565b600067ffffffffffffffff821115611c6457611c63611fe5565b5b602082029050919050565b6000819050919050565b6000819050602082019050919050565b6000819050919050565b6000819050919050565b6000819050919050565b600060029050919050565b600081519050919050565b600060019050919050565b600060029050919050565b600060049050919050565b6000602082019050919050565b6000602082019050919050565b6000602082019050919050565b6000602082019050919050565b6000602082019050919050565b600081905092915050565b600082825260208201905092915050565b600081905092915050565b600081905092915050565b600081905092915050565b600081905092915050565b600082825260208201905092915050565b6000611d8382611e7a565b9150611d8e83611e7a565b9250827fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff03821115611dc357611dc2611f87565b5b828201905092915050565b6000611dd982611e84565b9150611de483611e84565b92508263ffffffff03821115611dfd57611dfc611f87565b5b828201905092915050565b6000611e1382611e7a565b9150611e1e83611e7a565b925082821015611e3157611e30611f87565b5b828203905092915050565b6000611e4782611e5a565b9050919050565b60008115159050919050565b600073ffffffffffffffffffffffffffffffffffffffff82169050919050565b6000819050919050565b600063ffffffff82169050919050565b6000611e9f82611ea6565b9050919050565b6000611eb182611e5a565b9050919050565b6000611ec382611eca565b9050919050565b6000611ed582611e5a565b9050919050565b611ee582612014565b810181811067ffffffffffffffff82111715611f0457611f03611fe5565b5b80604052505050565b6000611f1882611e7a565b91507fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff821415611f4b57611f4a611f87565b5b600182019050919050565b6000611f6182611e7a565b9150611f6c83611e7a565b925082611f7c57611f7b611fb6565b5b828206905092915050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601160045260246000fd5b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601260045260246000fd5b7f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b6000601f19601f8301169050919050565b7f47616d652069732066756c6c0000000000000000000000000000000000000000600082015250565b7f496e76616c696420626f61726420737461746520285a4b290000000000000000600082015250565b7f496e76616c69642047616d652049440000000000000000000000000000000000600082015250565b7f496e76616c6964206d6f766520285a4b29000000000000000000000000000000600082015250565b7f496e76616c6964204d6f76652028592900000000000000000000000000000000600082015250565b7f4e6f7420616c6c6f77656420746f206a6f696e20796f7572206f776e2067616d60008201527f6500000000000000000000000000000000000000000000000000000000000000602082015250565b7f496e76616c6964204d6f76652028582900000000000000000000000000000000600082015250565b7f4e6f7420796f7572207475726e21000000000000000000000000000000000000600082015250565b61219c81611e4e565b81146121a757600080fd5b50565b6121b381611e7a565b81146121be57600080fd5b50565b6121ca81611e84565b81146121d557600080fd5b5056fea264697066735822122006eb7d8c8f2aafd49f0e26be8bcfb5f2cc50d9bf666ca6405303a31ec361e86d64736f6c63430008040033";

export class Battleship__factory extends ContractFactory {
  constructor(
    ...args: [signer: Signer] | ConstructorParameters<typeof ContractFactory>
  ) {
    if (args.length === 1) {
      super(_abi, _bytecode, args[0]);
    } else {
      super(...args);
    }
  }

  deploy(
    _createVerifier: string,
    _moveVerifier: string,
    overrides?: Overrides & { from?: string | Promise<string> }
  ): Promise<Battleship> {
    return super.deploy(
      _createVerifier,
      _moveVerifier,
      overrides || {}
    ) as Promise<Battleship>;
  }
  getDeployTransaction(
    _createVerifier: string,
    _moveVerifier: string,
    overrides?: Overrides & { from?: string | Promise<string> }
  ): TransactionRequest {
    return super.getDeployTransaction(
      _createVerifier,
      _moveVerifier,
      overrides || {}
    );
  }
  attach(address: string): Battleship {
    return super.attach(address) as Battleship;
  }
  connect(signer: Signer): Battleship__factory {
    return super.connect(signer) as Battleship__factory;
  }
  static readonly bytecode = _bytecode;
  static readonly abi = _abi;
  static createInterface(): BattleshipInterface {
    return new utils.Interface(_abi) as BattleshipInterface;
  }
  static connect(
    address: string,
    signerOrProvider: Signer | Provider
  ): Battleship {
    return new Contract(address, _abi, signerOrProvider) as Battleship;
  }
}
