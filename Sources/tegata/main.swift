import Foundation
import TegataCommand

exit(TegataCommand.run(Array(CommandLine.arguments.dropFirst()), style: .detect()))
